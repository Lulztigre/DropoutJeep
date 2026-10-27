import email
import imaplib


def fetch_emails(imap_server, imap_user, imap_pass, folder="INBOX", mark_seen=True, limit=None):
    """Fetch unseen messages from an IMAP mailbox.

    Messages are flagged \\Seen after being fetched. Without that the next poll
    returns the same DSNs and every bounce is recorded again, which inflates the
    bounce count for the rest of the engagement.
    """
    messages = []
    mail = None
    try:
        mail = imaplib.IMAP4_SSL(imap_server)
        mail.login(imap_user, imap_pass)
        mail.select(folder)
        result, data = mail.search(None, 'UNSEEN')
        if result != 'OK' or not data or not data[0]:
            return messages
        mail_ids = data[0].split()
        if limit:
            mail_ids = mail_ids[-int(limit):]
        for num in mail_ids:
            result, msg_data = mail.fetch(num, '(RFC822)')
            if result != 'OK' or not msg_data or not msg_data[0]:
                continue
            raw = msg_data[0][1]
            messages.append(email.message_from_bytes(raw))
            if mark_seen:
                try:
                    mail.store(num, '+FLAGS', '\\Seen')
                except Exception:
                    pass
        return messages
    except Exception as e:
        print(f"[!] IMAP fetch error: {e}")
        return messages
    finally:
        if mail is not None:
            try:
                mail.logout()
            except Exception:
                pass
