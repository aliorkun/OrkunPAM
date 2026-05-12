using System.IO.Compression;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml;
using Microsoft.EntityFrameworkCore;
using OrkunPAM.Domain.Entities.Identity;
using OrkunPAM.Domain.Enums;
using OrkunPAM.Identity.Services;
using OrkunPAM.Persistence;
using OrkunPAM.Persistence.Services;

namespace OrkunPAM.WebAPI.Endpoints;

public static class SamlAuthEndpoints
{
    private const string SpEntityId = "OrkunPAM";

    public static void MapSamlAuthEndpoints(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("/api/v1/auth/saml").WithTags("SAML Auth").AllowAnonymous();

        // SP-initiated login: redirect browser to the configured IdP SSO URL
        group.MapGet("/login", async (Guid? providerId, HttpContext ctx, OrkunPamDbContext db) =>
        {
            var provider = providerId.HasValue
                ? await db.SamlProviders.FindAsync(providerId.Value)
                : await db.SamlProviders.FirstOrDefaultAsync(p => p.IsEnabled);

            if (provider == null || !provider.IsEnabled)
                return Results.BadRequest(new { success = false, errors = new[] { "SAML provider not found or disabled" } });

            var idpSsoUrl = ExtractIdpSsoUrl(provider);
            if (string.IsNullOrEmpty(idpSsoUrl))
                return Results.BadRequest(new { success = false, errors = new[] { "IdP SSO URL not configured. Set AssertionConsumerUrl on the SAML provider or provide MetadataXml." } });

            var acsUrl = $"{ctx.Request.Scheme}://{ctx.Request.Host}/api/v1/auth/saml/acs";
            var requestId = "_" + Guid.NewGuid().ToString("N");
            var relayState = provider.Id.ToString();

            var authnRequestXml = BuildAuthnRequestXml(requestId, idpSsoUrl, acsUrl, SpEntityId);
            var redirectUrl = BuildRedirectUrl(idpSsoUrl, authnRequestXml, relayState);

            return Results.Redirect(redirectUrl);
        });

        // ACS: Assertion Consumer Service — IdP POSTs SAMLResponse here (HTTP-POST binding)
        group.MapPost("/acs", async (
            HttpContext ctx, OrkunPamDbContext db,
            IJwtTokenService jwt, IAuditService audit, ILogger<Program> log) =>
        {
            if (!ctx.Request.HasFormContentType)
                return Results.BadRequest(new { success = false, errors = new[] { "Expected application/x-www-form-urlencoded POST from IdP" } });

            var form = await ctx.Request.ReadFormAsync();
            var samlResponseBase64 = form["SAMLResponse"].ToString();
            var relayState = form["RelayState"].ToString();
            var clientIp = ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown";

            if (string.IsNullOrEmpty(samlResponseBase64))
                return Results.BadRequest(new { success = false, errors = new[] { "Missing SAMLResponse field" } });

            // Resolve provider via RelayState (set by SP-initiated flow) or default enabled provider
            SamlProvider? provider = null;
            if (Guid.TryParse(relayState, out var providerId))
                provider = await db.SamlProviders.FindAsync(providerId);
            provider ??= await db.SamlProviders.FirstOrDefaultAsync(p => p.IsEnabled);

            if (provider == null || !provider.IsEnabled)
                return Results.BadRequest(new { success = false, errors = new[] { "No active SAML provider found" } });

            // Parse and validate SAML assertion
            SamlAssertionResult assertionResult;
            try
            {
                assertionResult = ParseAndValidateSamlResponse(samlResponseBase64, provider);
            }
            catch (Exception ex)
            {
                log.LogWarning("SAML assertion validation failed (provider={Provider}, IP={Ip}): {Msg}",
                    provider.Name, clientIp, ex.Message);
                await audit.LogAsync("Auth", "SAML_LOGIN_FAILED", null, null, clientIp,
                    "SamlProvider", provider.Id.ToString(),
                    new { provider = provider.Name, error = ex.Message },
                    AuditOutcome.Failure);
                return Results.Json(new { success = false, errors = new[] { "SAML assertion validation failed" } }, statusCode: 401);
            }

            // Find or auto-provision SAML user
            var user = await db.Users
                .Include(u => u.UserRoles).ThenInclude(ur => ur.Role).ThenInclude(r => r.RolePermissions)
                .Include(u => u.UserGroups).ThenInclude(ug => ug.Group)
                    .ThenInclude(g => g.GroupRoles).ThenInclude(gr => gr.Role)
                    .ThenInclude(r => r.RolePermissions)
                .FirstOrDefaultAsync(u => u.AuthSource == AuthSource.Saml
                    && u.ExternalId == assertionResult.NameId);

            if (user == null)
            {
                var username = assertionResult.Email ?? assertionResult.NameId;
                if (username.Length > 100) username = username[..100];
                var normalized = username.ToUpperInvariant();

                // Avoid collision with existing local users
                if (await db.Users.AnyAsync(u => u.NormalizedUsername == normalized))
                    normalized = normalized + "_SAML";

                user = new User
                {
                    Username = username,
                    NormalizedUsername = normalized,
                    Email = assertionResult.Email,
                    DisplayName = assertionResult.DisplayName,
                    AuthSource = AuthSource.Saml,
                    ExternalId = assertionResult.NameId,
                    Status = UserStatus.Active
                };
                db.Users.Add(user);
                await db.SaveChangesAsync();
                log.LogInformation("Auto-provisioned SAML user '{User}' from provider '{Provider}'",
                    user.Username, provider.Name);
            }

            // Collect roles and permissions from direct assignments and group membership
            var roles = new HashSet<string>();
            var permissions = new HashSet<string>();
            foreach (var ur in user.UserRoles)
            {
                roles.Add(ur.Role.Name);
                foreach (var rp in ur.Role.RolePermissions)
                    permissions.Add(rp.PermissionCode);
            }
            foreach (var ug in user.UserGroups)
                foreach (var gr in ug.Group.GroupRoles)
                {
                    roles.Add(gr.Role.Name);
                    foreach (var rp in gr.Role.RolePermissions)
                        permissions.Add(rp.PermissionCode);
                }

            // Issue JWT (IdP handled authentication so mfa_verified = true)
            var tokenResult = jwt.GenerateTokens(
                user.Id, user.Username, user.DisplayName ?? user.Username,
                AuthSource.Saml.ToString(), roles, permissions, mfaVerified: true);

            if (tokenResult.IsFailure)
            {
                log.LogError("JWT generation failed for SAML user '{User}'", user.Username);
                return Results.Json(new { success = false, errors = new[] { "Token generation failed" } }, statusCode: 500);
            }

            user.RecordLoginSuccess(clientIp);
            await db.SaveChangesAsync();

            await audit.LogAsync("Auth", "SAML_LOGIN_SUCCESS", user.Id, user.Username, clientIp,
                "SamlProvider", provider.Id.ToString(), new { provider = provider.Name });

            log.LogInformation("SAML login success: user '{User}' via '{Provider}' (IP={Ip})",
                user.Username, provider.Name, clientIp);

            // Redirect browser to Blazor callback page with the access token
            var callbackUrl = "/saml-callback?token=" + Uri.EscapeDataString(tokenResult.Value.AccessToken);
            return Results.Redirect(callbackUrl);
        });
    }

    // -------------------------------------------------------------------------
    // SAML XML construction
    // -------------------------------------------------------------------------

    private static string BuildAuthnRequestXml(
        string id, string idpSsoUrl, string acsUrl, string spEntityId)
    {
        var issueInstant = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ");
        return $"""
            <samlp:AuthnRequest
                xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                ID="{id}"
                Version="2.0"
                IssueInstant="{issueInstant}"
                Destination="{XmlEsc(idpSsoUrl)}"
                AssertionConsumerServiceURL="{XmlEsc(acsUrl)}"
                ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST">
                <saml:Issuer>{XmlEsc(spEntityId)}</saml:Issuer>
                <samlp:NameIDPolicy
                    Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
                    AllowCreate="true"/>
            </samlp:AuthnRequest>
            """;
    }

    private static string BuildRedirectUrl(string idpSsoUrl, string authnRequestXml, string relayState)
    {
        // HTTP-Redirect binding: raw DEFLATE (RFC 1951) → base64 → URL-encode
        var xmlBytes = Encoding.UTF8.GetBytes(authnRequestXml.Trim());
        using var ms = new MemoryStream();
        using (var deflate = new DeflateStream(ms, CompressionLevel.Optimal, leaveOpen: true))
            deflate.Write(xmlBytes);

        var encoded = Uri.EscapeDataString(Convert.ToBase64String(ms.ToArray()));
        var sep = idpSsoUrl.Contains('?') ? "&" : "?";
        return $"{idpSsoUrl}{sep}SAMLRequest={encoded}&RelayState={Uri.EscapeDataString(relayState)}";
    }

    private static string XmlEsc(string s) => System.Security.SecurityElement.Escape(s) ?? s;

    // -------------------------------------------------------------------------
    // SAML response parsing and validation
    // -------------------------------------------------------------------------

    private sealed record SamlAssertionResult(string NameId, string? Email, string? DisplayName);

    private static SamlAssertionResult ParseAndValidateSamlResponse(
        string samlResponseBase64, SamlProvider provider)
    {
        var xmlBytes = Convert.FromBase64String(samlResponseBase64);
        var xml = Encoding.UTF8.GetString(xmlBytes);

        var doc = new XmlDocument { PreserveWhitespace = true };
        doc.LoadXml(xml);

        var ns = new XmlNamespaceManager(doc.NameTable);
        ns.AddNamespace("samlp", "urn:oasis:names:tc:SAML:2.0:protocol");
        ns.AddNamespace("saml", "urn:oasis:names:tc:SAML:2.0:assertion");
        ns.AddNamespace("ds", "http://www.w3.org/2000/09/xmldsig#");

        // Verify IdP returned Success status
        var statusCode = doc.SelectSingleNode("//samlp:StatusCode", ns)?.Attributes?["Value"]?.Value;
        if (statusCode != "urn:oasis:names:tc:SAML:2.0:status:Success")
            throw new InvalidOperationException($"IdP returned non-success status: {statusCode}");

        // Validate XML digital signature with IdP certificate (if available)
        var idpCert = LoadIdpCertificate(provider);
        if (idpCert != null)
            ValidateXmlSignature(doc, idpCert);

        // Validate time conditions (allow ±5 min clock skew)
        var now = DateTime.UtcNow;
        var conditions = doc.SelectSingleNode("//saml:Conditions", ns);
        if (conditions != null)
        {
            var nbAttr = conditions.Attributes?["NotBefore"]?.Value;
            var nooaAttr = conditions.Attributes?["NotOnOrAfter"]?.Value;

            if (nbAttr != null)
            {
                var notBefore = DateTime.Parse(nbAttr, null, System.Globalization.DateTimeStyles.RoundtripKind);
                if (notBefore > now.AddMinutes(5))
                    throw new InvalidOperationException($"Assertion not yet valid (NotBefore={nbAttr})");
            }
            if (nooaAttr != null)
            {
                var notOnOrAfter = DateTime.Parse(nooaAttr, null, System.Globalization.DateTimeStyles.RoundtripKind);
                if (notOnOrAfter < now.AddMinutes(-5))
                    throw new InvalidOperationException($"Assertion expired (NotOnOrAfter={nooaAttr})");
            }
        }

        // Extract NameID (required)
        var nameId = doc.SelectSingleNode("//saml:NameID", ns)?.InnerText?.Trim()
            ?? throw new InvalidOperationException("NameID missing from SAML assertion");

        // Extract standard attribute claims (email, display name)
        string? email = null;
        string? displayName = null;
        var attrNodes = doc.SelectNodes("//saml:Attribute", ns);
        if (attrNodes != null)
        {
            foreach (XmlNode attr in attrNodes)
            {
                var attrName = attr.Attributes?["Name"]?.Value ?? "";
                var attrValue = attr.SelectSingleNode("saml:AttributeValue", ns)?.InnerText?.Trim();
                if (string.IsNullOrEmpty(attrValue)) continue;

                // Match common email attribute names (WS-Fed, Azure AD, Okta, generic)
                if (attrName.EndsWith("emailaddress", StringComparison.OrdinalIgnoreCase)
                    || attrName.Equals("email", StringComparison.OrdinalIgnoreCase)
                    || attrName.Equals("mail", StringComparison.OrdinalIgnoreCase)
                    || attrName.Equals("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress", StringComparison.OrdinalIgnoreCase))
                    email = attrValue;

                // Match common display name attribute names
                else if (attrName.EndsWith("displayname", StringComparison.OrdinalIgnoreCase)
                    || attrName.EndsWith("/name", StringComparison.OrdinalIgnoreCase)
                    || attrName.Equals("displayName", StringComparison.OrdinalIgnoreCase))
                    displayName ??= attrValue;
            }
        }

        // If NameID is an email address, use it as email fallback
        if (email == null && nameId.Contains('@'))
            email = nameId;

        return new SamlAssertionResult(nameId, email, displayName);
    }

    private static void ValidateXmlSignature(XmlDocument doc, X509Certificate2 idpCert)
    {
        var sigNodes = doc.GetElementsByTagName("Signature", "http://www.w3.org/2000/09/xmldsig#");
        if (sigNodes.Count == 0)
            throw new InvalidOperationException("SAML response contains no XML digital signature");

        var signedXml = new SignedXml(doc);
        signedXml.LoadXml((XmlElement)sigNodes[0]);

        if (!signedXml.CheckSignature(idpCert, verifySignatureOnly: true))
            throw new CryptographicException("SAML XML signature verification failed");
    }

    // -------------------------------------------------------------------------
    // Provider configuration helpers
    // -------------------------------------------------------------------------

    private static string? ExtractIdpSsoUrl(SamlProvider provider)
    {
        // Try parsing from standard IdP metadata XML first
        if (!string.IsNullOrEmpty(provider.MetadataXml) && provider.MetadataXml.TrimStart().StartsWith('<'))
        {
            try
            {
                var doc = new XmlDocument();
                doc.LoadXml(provider.MetadataXml);
                var ns = new XmlNamespaceManager(doc.NameTable);
                ns.AddNamespace("md", "urn:oasis:names:tc:SAML:2.0:metadata");

                // Prefer HTTP-Redirect binding; fall back to first SSO service
                var ssoNode =
                    doc.SelectSingleNode("//md:SingleSignOnService[@Binding='urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect']", ns)
                    ?? doc.SelectSingleNode("//md:SingleSignOnService", ns);

                var url = ssoNode?.Attributes?["Location"]?.Value;
                if (!string.IsNullOrEmpty(url)) return url;
            }
            catch { /* fall through to manual field */ }
        }

        // Fall back: admin has stored the IdP SSO URL in AssertionConsumerUrl
        return provider.AssertionConsumerUrl;
    }

    private static X509Certificate2? LoadIdpCertificate(SamlProvider provider)
    {
        if (string.IsNullOrEmpty(provider.MetadataXml)) return null;

        // Case 1: full IdP metadata XML — parse certificate from KeyDescriptor
        if (provider.MetadataXml.TrimStart().StartsWith('<'))
        {
            try
            {
                var doc = new XmlDocument();
                doc.LoadXml(provider.MetadataXml);
                var ns = new XmlNamespaceManager(doc.NameTable);
                ns.AddNamespace("md", "urn:oasis:names:tc:SAML:2.0:metadata");
                ns.AddNamespace("ds", "http://www.w3.org/2000/09/xmldsig#");

                var certNode =
                    doc.SelectSingleNode("//md:KeyDescriptor[@use='signing']//ds:X509Certificate", ns)
                    ?? doc.SelectSingleNode("//ds:X509Certificate", ns);

                if (certNode != null)
                {
                    var b64 = certNode.InnerText.Replace("\n", "").Replace("\r", "").Replace(" ", "");
                    return new X509Certificate2(Convert.FromBase64String(b64));
                }
            }
            catch { }
        }

        // Case 2: bare PEM certificate stored in MetadataXml
        if (provider.MetadataXml.StartsWith("-----BEGIN CERTIFICATE-----"))
        {
            try { return X509Certificate2.CreateFromPem(provider.MetadataXml); }
            catch { }
        }

        return null; // Certificate not available — signature validation will be skipped
    }
}
