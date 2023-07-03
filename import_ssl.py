import ssl
import socket
import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import smtplib


def check_ssl_expiry(url):
    # Get the host and port from the URL
    host = url.split("://")[-1].split("/")[0]
    port = 443  # Default HTTPS port

    # Create a secure SSL context
    context = ssl.create_default_context()

    # Establish a connection with the server
    with socket.create_connection((host, port)) as sock:
        with context.wrap_socket(sock, server_hostname=host) as ssock:
            # Get the SSL certificate
            cert = ssock.getpeercert()
            cert_subject = cert["subject"]

            # Extract the "notAfter" field from the certificate
            expiry_date = datetime.datetime.strptime(
                cert["notAfter"], "%b %d %H:%M:%S %Y %Z"
            )

            # Get the current date and time
            current_date = datetime.datetime.now()

            # Calculate the remaining days until the certificate expires
            remaining_days = (expiry_date - current_date).days

            # Return the remaining days
            return cert_subject, expiry_date, remaining_days


def read_lines(filename):
    with open(filename, "r") as file:
        for line in file:
            yield line.rstrip()


def send_email(toaddr, FileName):
    fromaddr = "EAI.Admin.CGZ@noreply.com"
    msg = MIMEMultipart("alternative")
    msg["From"] = fromaddr
    msg["To"] = toaddr
    msg["Subject"] = "TIBCO DOMAIN NLB CERTIFICATE EXPIRY REPORT"

    body = open(FileName).read()
    msg.attach(MIMEText(body, "html"))

    server = smtplib.SMTP("smtp.server.com", 25)
    text = msg.as_string()
    server.sendmail(fromaddr, toaddr.split(","), text)
    server.quit()


def html_start(outfile):
    with open(outfile, "w") as f4:
        f4.write(
            '<!DOCTYPE html><html><head> <meta name="description" content="NLB CERTIFICATE EXPIRY REPORT"> <meta name="author" content="Satyaprakash Prasad"> </head>'
        )
        f4.write(
            "<style> h1 {text-align: center;} table { border-collapse: collapse; width: 100%; } th, td { border: 1px solid #ddd; text-align: left; padding: 8px; } tr:nth-child(even) { background-color: #F2F2F2; } th { background-color: #4CAF50; color: white; } </style>"
        )
        f4.write("<body> <h1><u>NLB Certificate Expiry Details</u></h1>")
        f4.write(
            "<table><tr><th>Environment</th><th>URL</th><th>Common Name</th><th>Expiry (DD-MM-YYYY)</th><th>Days Remaining</th><th>Has Expired</th></tr>"
        )


def html_content(outfile, env, url, cn, exp_date, days_to_expire, expired):
    with open(outfile, "a") as f4:
        # f4.write(f'<tr><td>{env}</td><td>{state}</td><td>{cn}</td><td>{exp_date}</td><td>{days_to_expire}</td><td>{expired}</td></tr>')
        f4.write(
            "<tr><td>{0}</td><td>{1}</td><td>{2}</td><td>{3}</td><td>{4}</td><td>{5}</td></tr>".format(
                env, url, cn, exp_date, days_to_expire, expired
            )
        )


def html_end(outfile):
    with open(outfile, "a") as f4:
        f4.write("</table></body></html>")


# Main
filename = "input_url.txt"
outfile = "out.html"
html_start(outfile)

for line in read_lines(filename):
    env, url = tuple(line.split("|"))
    cn, expiry_date, remaining_days = check_ssl_expiry(url)
    if remaining_days <= 0:
        expired = True
    else:
        expired = False
    html_content(outfile, env, url, cn, expiry_date, remaining_days, expired)
    print(f"The SSL certificate for {url} expires in {remaining_days} days.")


html_end(outfile)
