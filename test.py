import smtplib
from email.mime.text import MIMEText

EMAIL_ADDRESS = "kalasuttra@gmail.com"
EMAIL_PASSWORD = "svau jkwo fphb kprf"

msg = MIMEText("This is a test email.")
msg['Subject'] = "Test Email"
msg['From'] = EMAIL_ADDRESS
msg['To'] = "shubhamsheshank63@example.com"

try:
    with smtplib.SMTP('smtp.gmail.com', 587) as server:
        server.starttls()
        server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
        server.sendmail(EMAIL_ADDRESS, "recipient-email@example.com", msg.as_string())
    print("Email sent successfully.")
except Exception as e:
    print(f"Failed to send email: {e}")
