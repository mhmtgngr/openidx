# HR-Driven Joiner/Mover/Leaver (JML)

OpenIDX can treat an **HR system as the source of truth** for the employee
lifecycle. Instead of a joiner/mover/leaver originating from a directory sync or
a manual API call, it originates where HR actually records it (BambooHR today;
the same model covers Workday/SuccessFactors REST APIs), and OpenIDX reconciles
its user directory to match.

This is modeled as a **directory-connector type** (`hris` / `bamboohr`), so it
reuses the existing directory integration, scheduler, and sync-log machinery.

## Lifecycle mapping

| HR event | Detection | Action |
|----------|-----------|--------|
| **Joiner** | Employee present in HR, no local user (by `external_hr_id`) | Create a user (`source='hris'`, unusable password, HR attrs landed). Already-terminated employees are skipped. |
| **Mover** | HR attributes changed (title, department, name, status, dates) | Update the user; keeps the org chart current. |
| **Leaver** | Employee `Terminated` (even if still listed), or absent from the directory on a full sync | Deprovision: disable + stamp `termination_date` (or delete, per policy). |

A **manager pass** resolves each employee's HR supervisor id to a local
`manager_id` once all users exist, so the org chart is populated.

A **safety valve** refuses a full-sync deprovision when more than 40% of users
would be cut, guarding against a broken/partial HR fetch mass-terminating the
whole company.

## HR attributes on `users` (migration v96)

`employee_number`, `job_title`, `department`, `hire_date`, `termination_date`,
`employment_status` (`active|terminated|on_leave|pending`), and `external_hr_id`
(the HRIS-assigned id). All NULL for non-HR-sourced users. These also feed the
outbound-SCIM enterprise extension (department/employee number) and access
reviews.

## Configuration

An HRIS is a directory integration of type `hris` (or `bamboohr`) with this
config JSON:

```json
{
  "provider": "bamboohr",
  "subdomain": "acme",
  "api_key": "•••",
  "sync_interval": 60,
  "sync_enabled": true,
  "deprovision_action": "disable",
  "username_field": "email"
}
```

- `provider` — `bamboohr` (default). The connector is pluggable; add a provider
  by implementing `DirectoryConnector` and registering it in `newHRISConnector`.
- `subdomain` — BambooHR company subdomain. `base_url` may override the API root
  (Workday tenants / testing).
- `api_key` — sent as HTTP Basic username per BambooHR's scheme.
- `username_field` — `email` (default) or `employee_number` for the OpenIDX
  username.
- `deprovision_action` — `disable` (default, reversible) or `delete`.

## BambooHR API used

- `GET /v1/employees/directory` — the full active-employee directory. Presence
  implies active; a `Terminated` status or a past `terminationDate` marks a
  leaver.

## Operations

- **Manual sync:** trigger a directory sync as usual; the engine dispatches to
  the HRIS path by type.
- **Scheduled:** set `sync_interval` (minutes) + `sync_enabled` and the existing
  directory scheduler runs it.
- **First run:** run a full sync to backfill all employees; managers resolve on
  the same run.
