import flet as ft
import socket
import struct
import threading
import time
from datetime import datetime
import queue

# =========================
# DoIP / UDS Constants
# =========================
DOIP_PORT = 13400
DOIP_VERSION = 0x02
DOIP_INVERSE_VERSION = 0xFD
PAYLOAD_TYPE_DIAG = 0x8001
PAYLOAD_TYPE_ROUTING_ACTIVATION = 0x0005
PAYLOAD_TYPE_ROUTING_ACTIVATION_RESPONSE = 0x0006

TESTER_LA_OPTIONS = {
    "Mercedes Standard (0x000E)": 0x000E,
    "Mercedes Extended (0x0010)": 0x0010,
    "BMW Default (0x0E00)": 0x0E00,
    "FES/Gateway (0xF100)": 0xF100,
}

TESTER_LA_NOTES = {
    0x0E00: "BMW default diagnostic LA",
    0x000E: "Mercedes default DoIP LA",
    0x0010: "Mercedes extended LA",
    0xF100: "Gateway/FEM tester address",
}

DEFAULT_UDS_CMD = "10 01"

# =========================
# Core Logic Class
# =========================
class DoIPLogic:
    def __init__(self, log_callback):
        self.log_callback = log_callback

    def log(self, msg):
        timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        if msg.startswith("\n"):
            self.log_callback(f"\n[{timestamp}] {msg.lstrip()}")
        else:
            self.log_callback(f"[{timestamp}] {msg}")

    def build_doip_diag_message(self, uds_hex: str, tester_la: int, ecu_la: int, 
                                ver=DOIP_VERSION, inv_ver=DOIP_INVERSE_VERSION, 
                                payload_type=PAYLOAD_TYPE_DIAG) -> bytes:
        try:
            uds_payload = bytes.fromhex(uds_hex.replace(" ", ""))
            payload = struct.pack("!HH", tester_la, ecu_la) + uds_payload
            header = struct.pack("!BBHI", ver, inv_ver, payload_type, len(payload))
            return header + payload
        except Exception as e:
            self.log(f"Error building message: {e}")
            return None

    def send_routing_activation(self, sock, tester_la, activation_type=0x00):
        try:
            payload = struct.pack("!HB4s", tester_la, activation_type, b'\x00\x00\x00\x00')
            header = struct.pack("!BBHI", DOIP_VERSION, DOIP_INVERSE_VERSION, PAYLOAD_TYPE_ROUTING_ACTIVATION, len(payload))
            msg = header + payload
            
            self.log(f"TX Activation: {msg.hex(' ')}")
            sock.sendall(msg)
            
            resp = sock.recv(1024)
            self.log(f"RX Activation: {resp.hex(' ')}")
            
            if len(resp) < 8: return False, None
            
            _, _, rh_type, _ = struct.unpack("!BBHI", resp[:8])
            if rh_type != PAYLOAD_TYPE_ROUTING_ACTIVATION_RESPONSE: return False, None
            
            if len(resp) >= 13: # Header(8) + Tester(2) + Entity(2) + Code(1)
                _, r_entity, r_code = struct.unpack("!HHB", resp[8:13])
                if r_code == 0x10:
                    self.log(f"Activation OK. Target: {r_entity:04X}")
                    return True, r_entity
                else:
                    self.log(f"Activation Failed Code: {r_code:02X}")
                    return False, None
            return False, None
        except Exception as e:
            self.log(f"Activation Error: {e}")
            return False, None

    def send_uds(self, ecu_ip, uds_cmd, tester_la, ecu_la, doip_params=None):
        msg = self.build_doip_diag_message(uds_cmd, tester_la, ecu_la)
        if not msg: return

        act_type = 0x00
        if doip_params:
             act_type = doip_params.get('act_type', 0x00)

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        try:
            sock.connect((ecu_ip, DOIP_PORT))
            success, _ = self.send_routing_activation(sock, tester_la, act_type)
            if not success:
                self.log("Aborting: Activation Failed")
                return

            self.log(f"TX UDS: {msg.hex(' ')}")
            sock.sendall(msg)
            
            # Read loop
            end_time = time.time() + 4
            while time.time() < end_time:
                try:
                    resp = sock.recv(4096)
                    if not resp: break
                    self.log(f"RX: {resp.hex(' ')}")
                    
                    if len(resp) >= 8:
                        _, _, p_type, _ = struct.unpack("!BBHI", resp[:8])
                        if p_type == 0x8001: # Diag Message
                            self.parse_diag_response(resp)
                            return
                        elif p_type == 0x8002: # ACK
                            self.log("ACK Received, waiting for data...")
                            continue
                        elif p_type == 0x8003: # NACK
                            self.log("NACK Received.")
                            return
                except socket.timeout:
                    break
        except Exception as e:
            self.log(f"Connection Error: {e}")
        finally:
            sock.close()

    def parse_diag_response(self, data):
        if len(data) < 12: return
        payload = data[8:]
        sa, ta = struct.unpack("!HH", payload[:4])
        uds_data = payload[4:]
        self.log(f"Parsed Diag: From {sa:04X} to {ta:04X}")
        self.log(f"UDS Payload: {uds_data.hex(' ')}")


# =========================
# Flet Application
# =========================
def main(page: ft.Page):
    page.title = "Mercedes DoIP Tool (Flet)"
    page.theme_mode = ft.ThemeMode.DARK
    page.scroll = ft.ScrollMode.AUTO
    page.window_width = 450
    page.window_height = 800

    # LOGGING
    log_control = ft.TextField(
        multiline=True,
        read_only=True,
        min_lines=10,
        max_lines=10,
        text_size=12,
        expand=True,
        bgcolor=ft.colors.BLACK87,
        color=ft.colors.GREEN_400,
        font_family="Consolas,monospace"
    )

    def log_to_ui(msg):
        # Must run on main thread
        log_control.value += f"{msg}\n"
        page.update()

    logic = DoIPLogic(log_to_ui)
    
    # Discovery Shared State
    discovered_ecus = []

    # CONTROLS
    
    # 1. IP Selection
    dd_ip = ft.Dropdown(
        label="ECU IP",
        options=[],
        width=300
    )
    
    def on_ip_picked(e):
        val = dd_ip.value
        if val and " - " in val:
            _, la_part = val.split(" - ")
            txt_ecu_la.value = la_part
            page.update()

    dd_ip.on_change = on_ip_picked

    # 2. Tester LA
    def on_tester_dd_change(e):
        key = dd_tester.value
        if key in TESTER_LA_OPTIONS:
            val = TESTER_LA_OPTIONS[key]
            txt_tester_la.value = f"{val:04X}"
            lbl_note.value = f"Note: {TESTER_LA_NOTES.get(val, '')}"
            page.update()

    dd_tester = ft.Dropdown(
        label="Tester Profile",
        options=[ft.dropdown.Option(k) for k in TESTER_LA_OPTIONS.keys()],
        value="Mercedes Standard (0x000E)",
        on_change=on_tester_dd_change
    )
    
    txt_tester_la = ft.TextField(label="Tester LA (Hex)", value="000E", width=150)
    lbl_note = ft.Text("Note: Mercedes default DoIP LA", size=12, color=ft.colors.BLUE_200)

    # 3. ECU LA & UDS
    txt_ecu_la = ft.TextField(label="ECU LA (Hex)", width=150)
    txt_uds = ft.TextField(label="UDS Command (Hex)", value="10 01", expand=True)

    # 4. Settings (Collapsible)
    txt_act_type = ft.TextField(label="Act Type", value="00", width=80)
    
    # ACTIONS
    def on_btn_discovery(e):
        log_to_ui("\n=== Starting Discovery ===")
        
        def run_disc():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                sock.bind(('0.0.0.0', 0))
                sock.settimeout(2)
                
                vid_req = struct.pack("!BBHI", 0x02, 0xFD, 0x0001, 0x00000000)
                sock.sendto(vid_req, ("255.255.255.255", 13400))
                
                start = time.time()
                found = set()
                new_opts = []
                
                while time.time() - start < 2.5:
                    try:
                        data, addr = sock.recvfrom(4096)
                        ip = addr[0]
                        ecu_la = 0
                        if len(data) >= 8 + 19:
                            ecu_la = data[25] << 8 | data[26]
                        
                        entry = f"{ip} - {ecu_la:04X}"
                        if entry not in found:
                            found.add(entry)
                            new_opts.append(ft.dropdown.Option(entry))
                            logic.log(f"Found: {entry}")
                    except socket.timeout:
                        break
                    except Exception as err:
                        logic.log(f"Err: {err}")
                
                sock.close()
                if new_opts:
                    dd_ip.options = new_opts
                    dd_ip.value = new_opts[0].key
                    on_ip_picked(None)
                else:
                    logic.log("No ECUs found.")
                
                page.update()
            except Exception as ex:
                logic.log(f"Discovery Failed: {ex}")

        threading.Thread(target=run_disc, daemon=True).start()

    def on_btn_send(e):
        ip_str = dd_ip.value
        if not ip_str:
            logic.log("Error: No IP selected")
            return
        
        real_ip = ip_str.split(" - ")[0]
        
        try:
            t_la = int(txt_tester_la.value, 16)
            e_la = int(txt_ecu_la.value, 16)
            cmd = txt_uds.value
            
            # Simple spin up thread to not block UI
            threading.Thread(
                target=logic.send_uds,
                args=(real_ip, cmd, t_la, e_la),
                daemon=True
            ).start()
            
        except ValueError:
            logic.log("Error: Invalid Hex Format")

    def on_btn_reset(e):
        # 11 01
        txt_uds.value = "11 01"
        on_btn_send(e)
        
    def on_btn_clear(e):
        log_control.value = ""
        page.update()

    # LAYOUT
    page.add(
        ft.Text("Mercedes DoIP Tool", size=24, weight="bold"),
        ft.Divider(),
        ft.Row([ft.ElevatedButton("INIT DISCOVERY", on_click=on_btn_discovery, bgcolor=ft.colors.ORANGE_900)]),
        dd_ip,
        ft.Divider(),
        dd_tester,
        ft.Row([txt_tester_la, lbl_note]),
        ft.Divider(),
        ft.Row([txt_ecu_la, txt_act_type]),
        txt_uds,
        ft.Row([
            ft.ElevatedButton("SEND UDS", on_click=on_btn_send, bgcolor=ft.colors.BLUE_700),
            ft.ElevatedButton("RESET ECU", on_click=on_btn_reset, bgcolor=ft.colors.RED_700),
        ]),
        ft.Divider(),
        ft.Row([ft.Text("Log Output:"), ft.IconButton(ft.icons.DELETE, on_click=on_btn_clear)]),
        log_control
    )

if __name__ == "__main__":
    ft.app(target=main)
