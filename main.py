from flask import Flask, render_template, request, jsonify
from cryptography.fernet import Fernet
import hashlib
import base64

app = Flask(__name__)

# Глобальная переменная для хранения сообщений в памяти
messages = []

# Функция для шифрования текста
def encrypt_message(text, key):
    cipher_suite = Fernet(key)
    encrypted_text = cipher_suite.encrypt(text.encode())
    return encrypted_text.decode()

# Функция для расшифровки текста
def decrypt_message(encrypted_text, key):
    try:
        cipher_suite = Fernet(key)
        decrypted_text = cipher_suite.decrypt(encrypted_text.encode())
        return decrypted_text.decode()
    except Exception:
        return encrypted_text  # Если расшифровка невозможна, возвращаем исходный зашифрованный текст

def text_to_fernet_key(text):
    # Хэшируем текст с помощью SHA-256
    hash_object = hashlib.sha256(text.encode())
    # Преобразуем хэш в base64 и обрезаем до 32 байт
    key = base64.urlsafe_b64encode(hash_object.digest()[:32])
    return key.decode()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/send_message', methods=['POST'])
def send_message():
    message = request.form['message']
    encryption_text = request.form['encryption_key']

    try:
        # Преобразуем текстовый ключ в корректный формат
        encryption_key = text_to_fernet_key(encryption_text)
    except Exception as e:
        return jsonify({'error': f'Invalid encryption key: {str(e)}'}), 400

    # Шифруем сообщение
    encrypted_message = encrypt_message(message, encryption_key)

    # Сохраняем зашифрованное сообщение
    messages.append({'message': encrypted_message, 'key': encryption_key})

    return jsonify({'status': 'Message sent successfully'})

@app.route('/get_messages', methods=['GET'])
def get_messages():
    decryption_text = request.args.get('decryption_key')

    if not decryption_text:
        return jsonify({'messages': [msg['message'] for msg in messages]})  # Возвращаем зашифрованные сообщения

    try:
        # Преобразуем текстовый ключ в корректный формат
        decryption_key = text_to_fernet_key(decryption_text)
    except Exception as e:
        return jsonify({'error': f'Invalid decryption key: {str(e)}'}), 400

    # Расшифровываем сообщения
    decrypted_messages = []
    for msg in messages:
        decrypted_text = decrypt_message(msg['message'], decryption_key)
        decrypted_messages.append(decrypted_text)

    return jsonify({'messages': decrypted_messages})

@app.route('/generate_key', methods=['GET'])
def generate_key():
    text = request.args.get('text', '')  # Получаем текстовый ключ из запроса
    if not text:
        return jsonify({'error': 'Text for key generation is required'}), 400

    key = text_to_fernet_key(text)
    return jsonify({'key': key})

if __name__ == '__main__':
    app.run(debug=True)