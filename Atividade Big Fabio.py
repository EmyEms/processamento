# Instalação das bibliotecas necessárias
!pip install Pillow cryptography

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from PIL import Image
import hashlib
from google.colab import files  # Import necessário para o upload no Colab

# Funções para o menu de opções

# 1. Função para converter uma mensagem em binário
def message_to_binary(message):
    return ''.join([format(ord(char), '08b') for char in message])

# 2. Função para converter binário em texto
def binary_to_message(binary_data):
    binary_chars = [binary_data[i:i + 8] for i in range(0, len(binary_data), 8)]
    return ''.join([chr(int(binary_char, 2)) for binary_char in binary_chars])

# 3. Embutir texto em uma imagem usando esteganografia
def embed_text_in_image(image_path, message, output_image_path="imagem_alterada.png"):
    image = Image.open(image_path).convert('RGB')
    pixels = image.load()

    binary_message = message_to_binary(message) + '1111111111111110'
    data_index = 0

    for row in range(image.size[1]):
        for col in range(image.size[0]):
            if data_index < len(binary_message):
                r, g, b = pixels[col, row]
                r = (r & 254) | int(binary_message[data_index])
                data_index += 1
                if data_index < len(binary_message):
                    g = (g & 254) | int(binary_message[data_index])
                    data_index += 1
                if data_index < len(binary_message):
                    b = (b & 254) | int(binary_message[data_index])
                    data_index += 1
                pixels[col, row] = (r, g, b)

    image.save(output_image_path)
    print(f'Texto embutido e salvo em {output_image_path}')

# 4. Recuperar texto de uma imagem com esteganografia
def retrieve_text_from_image(image_path):
    image = Image.open(image_path).convert('RGB')
    pixels = image.load()

    binary_message = ''
    for row in range(image.size[1]):
        for col in range(image.size[0]):
            r, g, b = pixels[col, row]
            binary_message += str(r & 1)
            binary_message += str(g & 1)
            binary_message += str(b & 1)

    hidden_message = binary_to_message(binary_message)
    termination_index = hidden_message.find('þ')
    if termination_index != -1:
        hidden_message = hidden_message[:termination_index]  # Cortar na posição do caractere "þ"

    return hidden_message

# 5. Gerar hash de uma imagem
def generate_hash(image_path):
    md5_hash = hashlib.md5()
    with open(image_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            md5_hash.update(byte_block)
    return md5_hash.hexdigest()

# 6. Encriptar uma mensagem usando criptografia de chave pública
def encrypt_message(message, public_key):
    ciphertext = public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

# 7. Decriptar uma mensagem usando criptografia de chave privada
def decrypt_message(ciphertext, private_key):
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext

# Geração de chave pública e privada
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)
public_key = private_key.public_key()

# Função para obter caminho do arquivo
def get_file_path():
    choice = input("Deseja fazer upload do arquivo (U) ou digitar o caminho (D)? ").lower()
    if choice == 'u':
        uploaded = files.upload()
        return list(uploaded.keys())[0]
    elif choice == 'd':
        return input("Digite o caminho do arquivo: ")
    else:
        print("Escolha inválida. Tente novamente.")
        return get_file_path()

# Menu de opções
while True:
    print("\nMenu de opções:")
    print("(1) Embutir texto em uma imagem (Steganography)")
    print("(2) Recuperar texto de uma imagem (Steganography)")
    print("(3) Gerar hash de imagens original e alterada")
    print("(4) Encriptar a mensagem original com chave pública")
    print("(5) Decriptar mensagem encriptada com chave privada")
    print("(S ou s) Sair do menu e encerrar a aplicação")

    option = input("Escolha uma opção: ")

    if option == '1':
        image_path = get_file_path()
        message = input("Digite a mensagem a ser embutida: ")
        embed_text_in_image(image_path, message)

    elif option == '2':
        image_path = get_file_path()
        hidden_message = retrieve_text_from_image(image_path)
        print("Mensagem recuperada:", hidden_message)

    elif option == '3':
        print("Imagem original:")
        original_image_path = get_file_path()
        
        print("Imagem modificada:")
        modified_image_path = get_file_path()
        
        original_hash = generate_hash(original_image_path)
        modified_hash = generate_hash(modified_image_path)
        
        print("Hash da imagem original:", original_hash)
        print("Hash da imagem modificada:", modified_hash)
        if original_hash != modified_hash:
            print("Os hashes são diferentes: a imagem foi alterada.")
        else:
            print("Os hashes são iguais: a imagem não foi alterada.")

    elif option == '4':
        message = input("Digite a mensagem a ser encriptada: ").encode('utf-8')
        ciphertext = encrypt_message(message, public_key)
        print("Mensagem encriptada:", ciphertext)

    elif option == '5':
        ciphertext = input("Digite a mensagem encriptada (em bytes): ")
        decrypted_message = decrypt_message(eval(ciphertext), private_key)
        print("Mensagem decriptada:", decrypted_message.decode('utf-8'))

    elif option.lower() == 's':
        print("Saindo do programa.")
        break

    else:
        print("Opção inválida. Por favor, tente novamente.")
