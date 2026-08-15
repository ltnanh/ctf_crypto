import json
import base64
import socket
import time

host = "mta-ctf-60.id.vn"
port = 6004

def get_session():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    # Đọc banner khởi tạo
    while True:
        data = s.recv(1024).decode()
        if "> " in data: break
    
def send_and_recv(s, req_dict):
    s.sendall(json.dumps(req_dict).encode() + b"\n")
    resp = ""
    while True:
        d = s.recv(1024).decode()
        if not d: break
        resp += d
        if "\n" in resp and "> " in resp:
            break
    # Find the JSON part (it's before \n)
    json_part = resp.split("\n")[0]
    # If the response starts with prompt, strip it
    if json_part.startswith("> "):
        json_part = json_part[2:]
    return json.loads(json_part)

def get_session():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    # Đọc banner khởi tạo
    while True:
        data = s.recv(1024).decode()
        if "> " in data: break
    
    resp_dict = send_and_recv(s, {"method": "LOGIN", "params": {"username": "user01", "password": "1"}})
    session_b64 = resp_dict["data"]["session"]
    return s, session_b64

def xor_bytes(b1, b2):
    return bytes(x ^ y for x, y in zip(b1, b2))

def solve():
    print("[*] Đang chờ bot healthcheck request trúng Admin Product (tỉ lệ 1/8 mỗi 30s)...")
    while True:
        try:
            s, session_b64 = get_session()
            
            req_admin = {"method": "GET_PRODUCT", "params": {"session": session_b64, "product_name": "Admin Product"}}
            resp_admin_dict = send_and_recv(s, req_admin)
            
            req_flag = {"method": "GET_FLAG", "params": {"session": session_b64}}
            resp_flag_dict = send_and_recv(s, req_flag)
            
            s.close()

            
            # Nếu cả 2 đều trả về status="ok" nghĩa là ta đã hit trúng cache do bot tạo ra!
            if resp_admin_dict.get("status") == "ok" and resp_flag_dict.get("status") == "ok":
                print("[+] Cache hit thành công cho cả 2!")
                
                garbled_admin_b64 = resp_admin_dict["data"]["b64"]
                garbled_flag_b64 = resp_flag_dict["data"]["b64"]
                
                garbled_admin = base64.b64decode(garbled_admin_b64)
                garbled_flag = base64.b64decode(garbled_flag_b64)
                
                # Known plaintext của Admin Product (định dạng chuẩn JSON dumps của server)
                known_pt_dict = {
                    "owner": "admin",
                    "name": "Admin Product",
                    "description": "This is an admin-only product"
                }
                known_pt = json.dumps(known_pt_dict).encode()
                
                # Phục hồi mask = Keystream(admin) ^ Keystream(user)
                mask = xor_bytes(garbled_admin, known_pt)
                
                # XOR mask với dữ liệu lỗi của GET_FLAG để lấy Plaintext của Flag
                flag_json_bytes = xor_bytes(garbled_flag, mask)
                print("[+] Recovered GET_FLAG cache plaintext:")
                print(flag_json_bytes.decode(errors='ignore'))
                break
                
        except Exception as e:
            print("Error:", repr(e))
        time.sleep(1)

if __name__ == "__main__":
    solve()
