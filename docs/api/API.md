# Orkun PAM - API Reference

Base URL: `/api/v1`
Authentication: JWT Bearer Token
Response Format: JSON envelope

## Response Envelope
```json
{
  "success": true,
  "data": { ... },
  "errors": [],
  "meta": {
    "page": 1,
    "pageSize": 50,
    "totalCount": 1234
  }
}
```

---

## Authentication

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/auth/login` | Local login (username + password + optional MFA) |
| POST | `/auth/login/ad` | Active Directory login |
| GET | `/auth/saml/initiate` | SAML SSO redirect |
| POST | `/auth/saml/acs` | SAML assertion consumer |
| POST | `/auth/refresh` | Refresh JWT token |
| POST | `/auth/logout` | Revoke session |
| POST | `/auth/mfa/setup` | Begin TOTP setup |
| POST | `/auth/mfa/verify` | Verify MFA code |

## Users

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/users` | List users (paginated, filterable) |
| POST | `/users` | Create local user |
| GET | `/users/{id}` | Get user details |
| PUT | `/users/{id}` | Update user |
| DELETE | `/users/{id}` | Disable user (soft delete) |
| POST | `/users/{id}/reset-password` | Reset password |
| GET | `/users/{id}/permissions` | Effective permissions |
| GET | `/users/{id}/sessions` | User's active sessions |

## Groups

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/groups` | List groups |
| POST | `/groups` | Create group |
| GET | `/groups/{id}` | Get group |
| PUT | `/groups/{id}` | Update group |
| GET | `/groups/{id}/members` | List members |
| POST | `/groups/{id}/members` | Add members |
| DELETE | `/groups/{id}/members/{userId}` | Remove member |

## Roles

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/roles` | List roles |
| POST | `/roles` | Create custom role |
| GET | `/roles/{id}` | Get role with permissions |
| PUT | `/roles/{id}/permissions` | Update role permissions |

## LDAP Configuration

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/ldap-configs` | List LDAP configurations |
| POST | `/ldap-configs` | Create LDAP config |
| PUT | `/ldap-configs/{id}` | Update LDAP config |
| POST | `/ldap-configs/{id}/test` | Test connection |
| POST | `/ldap-configs/{id}/sync` | Trigger sync |

## SAML Providers

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/saml-providers` | List SAML providers |
| POST | `/saml-providers` | Create provider |
| PUT | `/saml-providers/{id}` | Update provider |
| GET | `/saml/metadata` | PAM SP metadata |

## Vault - Folders

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/vault/folders` | Folder tree |
| POST | `/vault/folders` | Create folder |
| PUT | `/vault/folders/{id}` | Update folder |
| DELETE | `/vault/folders/{id}` | Delete folder |
| GET | `/vault/folders/{id}/credentials` | Credentials in folder |

## Vault - Credentials

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/vault/credentials` | Search/filter credentials |
| POST | `/vault/credentials` | Create credential |
| GET | `/vault/credentials/{id}` | Get metadata (no password) |
| PUT | `/vault/credentials/{id}` | Update credential |
| DELETE | `/vault/credentials/{id}` | Delete credential |
| POST | `/vault/credentials/{id}/checkout` | Checkout (get password) |
| POST | `/vault/credentials/{id}/checkin` | Checkin |
| POST | `/vault/credentials/{id}/rotate` | Rotate password |
| GET | `/vault/credentials/{id}/history` | Password change history |
| POST | `/vault/credentials/{id}/share` | Share with user |
| POST | `/vault/credentials/{id}/reserve` | Reserve for future |
| POST | `/vault/credentials/{id}/approve` | Approve checkout request |

## Vault - Personal

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/vault/personal` | My personal vault |
| POST | `/vault/personal/credentials` | Add to personal vault |

## Vault - Rotation

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/vault/rotation-policies` | List rotation policies |
| POST | `/vault/rotation-policies` | Create policy |
| PUT | `/vault/rotation-policies/{id}` | Update policy |

## Vault - Discovery

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/vault/discovery-jobs` | List discovery jobs |
| POST | `/vault/discovery-jobs` | Create job |
| POST | `/vault/discovery-jobs/{id}/run` | Run now |
| GET | `/vault/discovered-accounts` | List discovered accounts |
| POST | `/vault/discovered-accounts/{id}/takeover` | Takeover account |

## Vault - Permissions

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/vault/permissions/{folderId}` | Get folder permissions |
| PUT | `/vault/permissions/{folderId}` | Set permissions |

## Devices

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/devices` | List devices (paginated, filterable) |
| POST | `/devices` | Create device |
| GET | `/devices/{id}` | Get device |
| PUT | `/devices/{id}` | Update device |
| DELETE | `/devices/{id}` | Delete device |
| POST | `/devices/{id}/check-reachability` | Check reachability |
| GET | `/devices/{id}/credentials` | Associated credentials |
| POST | `/devices/import/csv` | Import from CSV |
| POST | `/devices/import/ad-sync` | Import from AD |

## Device Groups

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/device-groups` | List groups |
| POST | `/device-groups` | Create group |
| POST | `/device-groups/{id}/members` | Add devices |
| DELETE | `/device-groups/{id}/members/{deviceId}` | Remove device |

## Platforms

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/platforms` | List platform templates |
| POST | `/platforms` | Create platform |
| PUT | `/platforms/{id}` | Update platform |

## Sessions

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/sessions/ssh/connect` | Request SSH session |
| POST | `/sessions/rdp/connect` | Request RDP session (returns .rdp file) |
| POST | `/sessions/vnc/connect` | Request VNC session |
| POST | `/sessions/sql/connect` | Request SQL session |
| GET | `/sessions` | List sessions (active + historical) |
| GET | `/sessions/active` | Active sessions only |
| GET | `/sessions/{id}` | Session details |
| POST | `/sessions/{id}/terminate` | Admin terminate |
| GET | `/sessions/{id}/recording` | Stream recording |
| GET | `/sessions/{id}/keystrokes` | Keystroke log |
| WS | `/sessions/{id}/monitor` | WebSocket live monitoring |
| WS | `/sessions/{id}/shadow` | WebSocket session shadowing |

## Workflows

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/workflows` | List workflow definitions |
| POST | `/workflows` | Create workflow |
| PUT | `/workflows/{id}` | Update workflow |
| GET | `/approval-requests` | List approval requests |
| GET | `/approval-requests/pending` | My pending approvals |
| POST | `/approval-requests/{id}/approve` | Approve |
| POST | `/approval-requests/{id}/deny` | Deny |

## AAPM

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/aapm/token` | Client credentials grant |
| GET | `/aapm/credentials/{id}` | Retrieve credential (API client auth) |
| GET | `/aapm/clients` | List API clients |
| POST | `/aapm/clients` | Create API client |
| PUT | `/aapm/clients/{id}` | Update client |
| GET | `/aapm/clients/{id}/access-log` | Access log |

## Analytics

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/analytics/risk-scores/users` | User risk scores |
| GET | `/analytics/risk-scores/sessions` | Session risk scores |
| GET | `/analytics/anomalies` | Detected anomalies |
| GET | `/analytics/alerts` | Alert history |
| POST | `/analytics/alerts/{id}/acknowledge` | Acknowledge alert |
| GET | `/analytics/uba/rules` | UBA rules |
| POST | `/analytics/uba/rules` | Create UBA rule |

## SIEM

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/integrations/siem` | SIEM configuration |
| PUT | `/integrations/siem` | Update SIEM config |
| POST | `/integrations/siem/test` | Test SIEM connection |

## Compliance

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/compliance/frameworks` | List compliance frameworks |
| GET | `/compliance/frameworks/{id}/assessment` | Assessment details |
| POST | `/compliance/evidence/export` | Export evidence bundle |
| GET | `/compliance/sod/rules` | SoD rules |
| GET | `/compliance/sod/violations` | SoD violations |
| GET | `/compliance/attestations` | Attestation campaigns |
| POST | `/compliance/attestations` | Create campaign |

## Reports

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/reports` | List report definitions |
| POST | `/reports/{id}/run` | Run report |
| GET | `/reports/{id}/export` | Export (format param) |
| GET | `/reports/schedules` | List schedules |
| POST | `/reports/schedules` | Create schedule |

## Dashboard

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/dashboard/widgets` | My widgets |
| PUT | `/dashboard/widgets` | Save layout |
| GET | `/dashboard/widgets/{type}/data` | Widget data |

## Audit Logs

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/audit-logs` | Search audit logs |
| GET | `/audit-logs/verify` | Verify log integrity |
| POST | `/audit-logs/export` | Export logs |

## System

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/system/health` | Health check |
| GET | `/system/config` | System configuration |
| PUT | `/system/config/{key}` | Update config |
| GET | `/system/jobs` | Background jobs |
| GET | `/system/license` | License info |
