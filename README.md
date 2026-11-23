# SecureWebBank

A responsive Flask banking website for a classroom demonstration. The UI supports demo registration and sign-in, account balances, deposits, withdrawals, verified sample transfers by account number or registered mobile number, transfer history, profile edits, password changes, notification preferences and logout confirmation.

> This is an academic prototype. Balances and transfers are simulated. Never enter real financial or personal information.

## Run locally

1. Install Python 3.10 or later.
2. In this folder, create and activate a virtual environment, then install dependencies:

   ```powershell
   py -m venv .venv
   .venv\Scripts\Activate.ps1
   pip install -r requirements.txt
   ```

3. Start the app and open `http://127.0.0.1:5055`:

   ```powershell
   python app.py
   ```

For testing from another device on the same Wi-Fi, run `Start SecureWebBank.bat`. It binds the demo app to the local network on port 5055. Open `http://<this-computer's-local-IP>:5055` on the other device. This is only for a trusted local network, not public internet hosting.

## Database setup

The app uses the configured PostgreSQL database when `DATABASE_URL` is set, for example:

```powershell
$env:DATABASE_URL = 'postgresql://user:password@localhost:5432/securewebbank'
$env:SECRET_KEY = 'a-long-random-secret-value'
$env:APP_ENV = 'production'
$env:DEMO_MODE = '0'
python app.py
```

On startup, it creates or extends the required customer, user, account, transaction and transfer tables and their indexes. When `DATABASE_URL` is set, demo mode defaults off unless `DEMO_MODE=1` is explicitly chosen. In production mode, the Demo customers link and directory are hidden, no demo recipient accounts are created, existing sample recipient accounts are disabled, and new accounts start at ₹0. If `DATABASE_URL` is not set, it uses the included SQLite demo database at `securewebbank.sqlite3`; local demo mode defaults on. No PostgreSQL server was configured with this project, so local testing uses SQLite unless you provide a PostgreSQL connection string.

For a published deployment, point `DATABASE_URL` at a clean PostgreSQL database. Turning off demo mode hides and disables the known sample recipients in an existing database but does not erase historical records.

Set a stable `SECRET_KEY` for local restarts so sessions remain valid. Keep the database URL and secret private. Do not enable Flask's debugger outside a local development machine.

## Demo recipient details

In local demo mode, the database includes three clearly labelled sample recipients so transfers can be shown without real data:

| Demo account | Account number | Registered demo mobile |
| --- | --- | --- |
| Ava Bennett | `SB-2048-1101` | `+919900000101` |
| Noah Williams | `SB-2048-1102` | `+919900000102` |
| Mia Chen | `SB-2048-1103` | `+919900000103` |

The sample balances are simulated. A new registration in demo mode receives ₹2,500 in simulated funds; outside demo mode it starts at ₹0. No sample transaction history is preloaded.

## Transfers and security behavior

- Account number transfers require the account holder name to match the stored customer profile.
- Mobile lookups match a registered mobile number on the backend and show the verified recipient before confirmation.
- Recipient confirmation is signed, bound to the logged-in user and expires after five minutes.
- The server validates the amount and available balance. It applies a successful sender debit, receiver credit, and transfer history record in one database transaction.
- Insufficient-funds attempts are recorded with a failed status without changing either balance.
- Passwords use salted PBKDF2-HMAC-SHA256 hashes. Protected browser forms use CSRF tokens; session cookies are HTTP-only and SameSite Lax.
- Notification preferences are saved for this demo; the app does not send real notifications.

## JSON endpoints

| Method | Endpoint | Purpose |
| --- | --- | --- |
| `GET` | `/api/v1/health` | Demo service status |
| `POST` | `/api/v1/auth/register` | Create a simulated user |
| `POST` | `/api/v1/auth/login` | Sign in and set a session cookie |
| `GET` | `/api/v1/banking/balance` | Authenticated balance |
| `POST` | `/api/v1/banking/deposit` | Authenticated demo deposit |
| `POST` | `/api/v1/banking/withdraw` | Authenticated demo withdrawal |
| `POST` | `/api/v1/recipients/verify-account` | Verify an account number and name |
| `POST` | `/api/v1/recipients/verify-mobile` | Look up a registered demo mobile |
| `GET` | `/api/v1/banking/transactions` | Authenticated transaction and transfer history |

The project is a local academic demo, not a production banking service or payment integration.

## Render production deployment

The project is prepared for Render with `render.yaml`, `gunicorn` in `requirements.txt`, and a pinned Python version in `.python-version`. The Render Blueprint defines a paid web service and a paid, private PostgreSQL database. Review Render's current pricing before creating the Blueprint; the paid plans are selected so the service stays on an always-on plan and the database is not subject to the free database's 30-day expiry.

### Environment variables

| Variable | Purpose | Render value |
| --- | --- | --- |
| `APP_ENV` | Enables production safeguards and secure session cookies. | `production` |
| `SECRET_KEY` | Signs session cookies. Keep it private and stable across deploys. | Generated by Render from `render.yaml` |
| `DATABASE_URL` | PostgreSQL connection string. The app uses this in place of SQLite. | Render's private connection string from the Blueprint database |
| `DEMO_MODE` | Controls sample customers and simulated starting balances. | `0` in production |
| `PORT` | HTTP port Gunicorn listens on. | Supplied by Render and used by the start command |
| `PYTHON_VERSION` | Python runtime version. | Pinned by `.python-version` |
| `FLASK_DEBUG` | Development debugger switch. | Leave unset in production |

Production startup fails if `DATABASE_URL` or `SECRET_KEY` is missing. HTTPS deployments set the session cookie's `Secure` flag. The app creates missing tables and indexes and only adds missing notification columns; it does not drop, truncate, or reset tables.

### Deploy

1. Keep the original `securewebbank.sqlite3` file on your computer. `.gitignore` excludes SQLite files from a new Git commit; it does not remove or change the local file. Do not commit that database or any secret values.
2. Create a GitHub repository with the contents of this project folder at the repository root, then push the files. Keep `render.yaml` at that root so Render finds it automatically.
3. In Render, choose **New > Blueprint**, connect the repository, and select the branch containing `render.yaml`.
4. Review the Blueprint's paid service and database plans and the price shown by Render, then create the resources. Render supplies `DATABASE_URL` from the private Postgres database and generates `SECRET_KEY`.
5. Wait for the first deploy to pass its `/api/v1/health` check. Open the HTTPS URL shown on the Render service page. Render assigns the service a stable `onrender.com` URL; no Cloudflare tunnel is involved.

The Blueprint creates a new PostgreSQL database. Your existing SQLite database remains intact on your computer and is not copied automatically, so existing local accounts, balances, and history will not appear in the new Render database until you perform a separate data migration. The application schema setup is additive and does not reset either database. Render's database allowlist is private-only; any planned migration from outside Render requires a temporary, restricted external IP rule and then restoring private-only access.

The Blueprint also enables automatic pull request previews and preview environments, expires inactive previews after seven days, and uses free compute for preview web/database resources. The production service is configured to auto-deploy on each commit to its linked branch. Render creates and updates previews from pull requests once the Blueprint is connected to GitHub; pushes to the linked branch deploy production. Preview behavior is controlled by the Blueprint fields described in [Render's Blueprint specification](https://render.com/docs/blueprint-spec).

Render references: [Deploy a Flask app](https://render.com/docs/deploy-flask), [Blueprint specification](https://render.com/docs/blueprint-spec), [set Python version](https://render.com/docs/python-version), and [free plan limitations](https://render.com/docs/free).
