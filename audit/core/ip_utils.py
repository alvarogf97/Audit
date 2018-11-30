import warnings
import netifaces
import smtplib
import socket
from audit.core.environment import Environment


# return local wifi interface ip and device name
def get_ip_info():
    ip_device = netifaces.gateways()['default'][netifaces.AF_INET][1]
    ip_gateway = netifaces.gateways()['default'][netifaces.AF_INET][0]
    ip = netifaces.ifaddresses(ip_device)[netifaces.AF_INET][0]["addr"]
    return ip, ip_device, ip_gateway


# send_IP: sended the IP(private and public) and machine name via e-mail
def send_ip(port, mail):
    gmail_user = 'reaperanalyzer@gmail.com'
    gmail_password = '@dminth0r'
    sent_from = gmail_user
    to = [mail]
    subject = 'IP'
    body = "Local IP: " + Environment().private_ip \
           + " Public IP: " + Environment().public_ip \
           + "\nMachine: " + socket.gethostname() \
           + "\nPort: " + str(port)
    email_text = """From: %s\nTo: %s\nSubject: %s\n\n%s
    """ % (sent_from, ", ".join(to), subject, body)
    try:
        server = smtplib.SMTP_SSL('smtp.gmail.com', 465)
        server.ehlo()
        server.login(gmail_user, gmail_password)
        server.sendmail(sent_from, to, email_text)
        server.close()
    except Exception as e:
        warnings.warn(str(e))
