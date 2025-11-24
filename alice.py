import socket
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519
# AQUI ESTÁ A MAGIA: Importamos do ficheiro protocolo.py
from protocol import Participante, SessaoSegura

HOST = '127.0.0.1'
PORT = 9999

print("\n--- ALICE (Cliente PQ) ---")
alice = Participante("Alice")

try:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        print(f"Conectado a {HOST}:{PORT}")
        
        # 1. Recebe Bundle do Bob (128 bytes)
        bundle_bytes = s.recv(128)
        
        bundle_bob = {
            'ik_publica': x25519.X25519PublicKey.from_public_bytes(bundle_bytes[:32]),
            'spk_publica': x25519.X25519PublicKey.from_public_bytes(bundle_bytes[32:64]),
            'opk_publica': x25519.X25519PublicKey.from_public_bytes(bundle_bytes[64:96]),
            'pq_publica': x25519.X25519PublicKey.from_public_bytes(bundle_bytes[96:])
        }
        
        sk_alice, info_bob = alice.iniciar_sessao_x3dh(bundle_bob)
        
        # 2. Envia Handshake: IK + EK + Ciphertext
        msg_inicial = (
            info_bob['ik_publica_iniciador'].public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw) +
            info_bob['ek_publica_iniciador'].public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw) +
            info_bob['pq_ciphertext']
        )
        s.sendall(msg_inicial)
        
        # 3. Inicia Chat
        sessao = SessaoSegura(sk_alice, iniciador=True)

        # Msg 1
        print("Enviando Msg 1...")
        s.sendall(sessao.cifrar("Olá Bob! Chave Quântica ativa?"))
        resp1 = s.recv(4096)
        print(f"Resposta 1: {sessao.decifrar(resp1)}")
        
        # Msg 2
        print("Enviando Msg 2...")
        s.sendall(sessao.cifrar("Teste de estabilidade."))
        resp2 = s.recv(4096)
        print(f"Resposta 2: {sessao.decifrar(resp2)}")

except ConnectionRefusedError:
    print("ERRO: O Bob não está ligado! Corre o bob.py primeiro.")