import socket

def get_IP():
    # IPv4 only for now
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('147.4.215.19', 9929))
        ret = s.getsockname()[0]
    except:
        ret = '127.0.0.1'
    finally:
        s.close()

    return ret
