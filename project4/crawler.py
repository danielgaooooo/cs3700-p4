import socket
import html
import html.parser
import urllib.parse
import xml

USERNAME='001258212'
PASSWORD='8ZTNFIX3'
HOST='fring.ccs.neu.edu'
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((socket.gethostbyname(HOST), 80))

def read():
    response = ''
    while True:
        recv = sock.recv(1024)
        if not recv:
            break
        response += str(recv)
    return response

# Returns the CSRF token and Session ID as a tuple, in that order
# This method is called prior to login
def get_tokens():

    header = 'GET /accounts/login/ HTTP/1.1\r\n'
    header += 'Connection: keep-alive\r\n'
    header += 'Host: ' + HOST + '\r\n\r\n'
    header_bytes = header.encode()
    sock.sendall(header_bytes)
    response = read()
    while True:
        recv = sock.recv(1024)
        if not recv:
            break
        response += str(recv)
    csrf_idx = response.find('csrftoken=') + 10
    sessionid_idx = response.find('sessionid=') + 10
    assert(csrf_idx > 0 and sessionid_idx > 0)
    csrf = response[csrf_idx:csrf_idx+32]
    sessionid = response[sessionid_idx:sessionid_idx+32]
    ret = (csrf, sessionid)
    return ret

def login():
    token_tuple = get_tokens()
    print("Retrieved csrf token: " + token_tuple[0])
    print("Retrieved session id: " + token_tuple[1])


    body = 'username=' + USERNAME
    body += '&password=' + PASSWORD
    body += '&csrfmiddlewaretoken=' + token_tuple[0]
    body += '&next=%2Ffakebook%2F\r\n\r\n'

    header = 'POST http://fring.ccs.neu.edu/accounts/login HTTP/1.1\r\n'
    header += 'Host: ' + HOST + '\r\n'
    header += 'Content-Length: ' + str(len(body)) + '\r\n'
    header += 'Cache-Control: max-age=0\r\n'
    header += 'Connection: keep-alive\r\n'
    header += 'Origin: http://fring.ccs.neu.edu\r\n'
    header += 'Upgrade-Insecure-Requests: 1\r\n'
    header += 'Content-Type: application/x-www-form-urlencoded\r\n'
    header += 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9\r\n'
    header += 'Referer: http://fring.ccs.neu.edu/accounts/login/?next=/fakebook/\r\n'
    header += 'Accept-Encoding: gzip, deflate\r\n'
    header += 'Accept-Language: en-US,en;q=0.9\r\n'
    header += 'Cookie: csrftoken='+ token_tuple[0] +'; sessionid=' + token_tuple[1] + '\r\n\r\n'

    header += body

    payload = header.encode()

    print("\nSENDING POST LOGIN REQUEST =============================")
    sock.sendall(payload)
    print(payload.decode())
    response = read()
    print("\nRECEIVED DATA: =========================================")
    print(response)

def main():
    login()

if __name__ == "__main__":
    main()