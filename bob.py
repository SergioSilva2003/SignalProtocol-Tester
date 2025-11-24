import socket
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519
# AQUI ESTÁ A MAGIA: Importamos do ficheiro protocolo.py
from protocol import Participante, SessaoSegura

HOST = '127.0.0.1'
PORT = 9999

print("\n--- BOB (Servidor PQ) ---")
bob = Participante("Bob")
bundle = bob.gerar_bundle_publico()

# Prepara Bundle: 4 chaves (IK, SPK, OPK, PQ) * 32 bytes = 128 bytes
b_bytes = b''.join([
    bundle['ik_publica'].public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw),
    bundle['spk_publica'].public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw),
    bundle['opk_publica'].public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw),
    bundle['pq_publica'].public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
])

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, PORT))
    s.listen()
    print(f"[Bob] À escuta na porta {PORT}...")
    
    conn, addr = s.accept()
    with conn:
        print(f"[Bob] Conexão de {addr}")
        conn.sendall(b_bytes)
        
        # Recebe Handshake da Alice: IK + EK + Ciphertext (96 bytes)
        info_a = conn.recv(96)
        
        ik_a = x25519.X25519PublicKey.from_public_bytes(info_a[:32])
        ek_a = x25519.X25519PublicKey.from_public_bytes(info_a[32:64])
        pq_ciphertext = info_a[64:96]
        
        sk_bob = bob.receber_sessao_x3dh({
            'ik_publica_iniciador': ik_a, 
            'ek_publica_iniciador': ek_a,
            'pq_ciphertext': pq_ciphertext
        })
        
        sessao = SessaoSegura(sk_bob, iniciador=False)
        
        while True:
            dados = conn.recv(4096)
            if not dados:
                print("[Bob] Alice desconectou.")
                break
            
            msg = sessao.decifrar(dados)
            if msg:
                print(f"\n[Bob] Recebido: '{msg}'")
                conn.sendall(sessao.cifrar("Recebido 5/5 (Modo PQ)"))