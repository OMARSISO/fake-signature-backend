#!/usr/bin/env python3
"""
Fake Signature Web Service - Production Backend
Веб-сервис для копирования цифровых подписей между PE файлами
"""

import os
import uuid
import tempfile
from datetime import datetime
from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from werkzeug.utils import secure_filename
from werkzeug.exceptions import RequestEntityTooLarge
import threading
import time

from sigthief_module import create_fake_signature, FakeSignatureError

app = Flask(__name__)
CORS(app)  # Разрешаем CORS для всех доменов

# Конфигурация
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB максимум
app.config['UPLOAD_FOLDER'] = '/tmp/fakesig_uploads'
app.config['RESULT_FOLDER'] = '/tmp/fakesig_results'
app.config['SECRET_KEY'] = 'fake-signature-web-service-secret-key'

# Создаем директории если их нет
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['RESULT_FOLDER'], exist_ok=True)

# Разрешенные расширения файлов
ALLOWED_EXTENSIONS = {'exe', 'dll', 'sys'}

# Хранилище результатов (в продакшене лучше использовать Redis)
results_storage = {}

def allowed_file(filename):
    """Проверка разрешенного расширения файла"""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def cleanup_old_files():
    """Очистка старых файлов (запускается в фоне)"""
    while True:
        try:
            current_time = time.time()
            # Удаляем файлы старше 1 часа
            for folder in [app.config['UPLOAD_FOLDER'], app.config['RESULT_FOLDER']]:
                for filename in os.listdir(folder):
                    filepath = os.path.join(folder, filename)
                    if os.path.isfile(filepath):
                        file_age = current_time - os.path.getctime(filepath)
                        if file_age > 3600:  # 1 час
                            os.remove(filepath)
            
            # Очищаем старые записи из хранилища результатов
            expired_keys = []
            for task_id, result_info in results_storage.items():
                if current_time - result_info['timestamp'] > 3600:
                    expired_keys.append(task_id)
            
            for key in expired_keys:
                del results_storage[key]
                
        except Exception as e:
            print(f"Ошибка при очистке файлов: {e}")
        
        time.sleep(300)  # Проверяем каждые 5 минут

# Запускаем фоновую очистку
cleanup_thread = threading.Thread(target=cleanup_old_files, daemon=True)
cleanup_thread.start()

@app.route('/')
def index():
    """Главная страница - возвращаем информацию об API"""
    return jsonify({
        'service': 'Fake Signature Web Service',
        'version': '1.0.0',
        'status': 'running',
        'endpoints': {
            'POST /api/process': 'Process files and copy signature',
            'GET /api/download/<task_id>': 'Download processed file',
            'GET /api/status': 'Service status'
        },
        'frontend': 'Deploy frontend separately and configure API_BASE_URL',
        'cors': 'enabled',
        'max_file_size': '100MB'
    })

@app.route('/api/status')
def status():
    """API для проверки статуса сервиса"""
    return jsonify({
        'status': 'running',
        'version': '1.0.0',
        'supported_formats': list(ALLOWED_EXTENSIONS),
        'max_file_size': '100MB',
        'active_tasks': len(results_storage),
        'service_name': 'Fake Signature Web Service',
        'timestamp': datetime.now().isoformat()
    })

@app.route('/api/process', methods=['POST'])
def process_files():
    """API для обработки файлов"""
    try:
        # Проверяем наличие файлов
        if 'signed_file' not in request.files or 'target_file' not in request.files:
            return jsonify({'error': 'Необходимо загрузить оба файла'}), 400
        
        signed_file = request.files['signed_file']
        target_file = request.files['target_file']
        
        # Проверяем, что файлы выбраны
        if signed_file.filename == '' or target_file.filename == '':
            return jsonify({'error': 'Файлы не выбраны'}), 400
        
        # Проверяем расширения файлов
        if not (allowed_file(signed_file.filename) and allowed_file(target_file.filename)):
            return jsonify({'error': 'Поддерживаются только файлы .exe, .dll, .sys'}), 400
        
        # Генерируем уникальный ID задачи
        task_id = str(uuid.uuid4())
        
        # Создаем безопасные имена файлов
        signed_filename = secure_filename(signed_file.filename)
        target_filename = secure_filename(target_file.filename)
        
        # Пути для сохранения
        signed_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{task_id}_signed_{signed_filename}")
        target_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{task_id}_target_{target_filename}")
        result_path = os.path.join(app.config['RESULT_FOLDER'], f"{task_id}_result_{target_filename}")
        
        # Сохраняем загруженные файлы
        signed_file.save(signed_path)
        target_file.save(target_path)
        
        # Обрабатываем файлы с помощью Fake Signature
        fake_signature = create_fake_signature()
        
        try:
            processed_path, output_filename = fake_signature.process_files(
                signed_path, target_path, result_path
            )
            
            # Сохраняем информацию о результате
            results_storage[task_id] = {
                'filename': output_filename,
                'path': processed_path,
                'timestamp': time.time(),
                'original_target_name': target_file.filename
            }
            
            # Формируем URL для скачивания
            download_url = f"/api/download/{task_id}"
            
            return jsonify({
                'success': True,
                'task_id': task_id,
                'download_url': download_url,
                'filename': f"signed_{target_file.filename}"
            })
            
        except FakeSignatureError as e:
            return jsonify({'error': str(e)}), 400
        
        finally:
            # Удаляем временные файлы
            try:
                if os.path.exists(signed_path):
                    os.remove(signed_path)
                if os.path.exists(target_path):
                    os.remove(target_path)
            except:
                pass
    
    except RequestEntityTooLarge:
        return jsonify({'error': 'Файл слишком большой (максимум 100MB)'}), 413
    except Exception as e:
        return jsonify({'error': f'Внутренняя ошибка сервера: {str(e)}'}), 500

@app.route('/api/download/<task_id>')
def download_file(task_id):
    """API для скачивания обработанного файла"""
    if task_id not in results_storage:
        return jsonify({'error': 'Файл не найден или срок действия истек'}), 404
    
    result_info = results_storage[task_id]
    file_path = result_info['path']
    
    if not os.path.exists(file_path):
        return jsonify({'error': 'Файл не найден на сервере'}), 404
    
    try:
        return send_file(
            file_path,
            as_attachment=True,
            download_name=f"signed_{result_info['original_target_name']}",
            mimetype='application/octet-stream'
        )
    except Exception as e:
        return jsonify({'error': f'Ошибка при скачивании файла: {str(e)}'}), 500

@app.errorhandler(413)
def too_large(e):
    """Обработчик ошибки превышения размера файла"""
    return jsonify({'error': 'Файл слишком большой (максимум 100MB)'}), 413

@app.errorhandler(404)
def not_found(e):
    """Обработчик 404 ошибки"""
    return jsonify({'error': 'Endpoint не найден'}), 404

@app.errorhandler(500)
def internal_error(e):
    """Обработчик внутренних ошибок сервера"""
    return jsonify({'error': 'Внутренняя ошибка сервера'}), 500

if __name__ == '__main__':
    print("🚀 Запуск Fake Signature Web Service...")
    print("📁 Папка загрузок:", app.config['UPLOAD_FOLDER'])
    print("📁 Папка результатов:", app.config['RESULT_FOLDER'])
    print("🌐 Сервис будет доступен по адресу: http://0.0.0.0:5000")
    print("🔗 CORS включен для всех доменов")
    print("⚠️  ВНИМАНИЕ: Этот инструмент предназначен только для исследовательских целей!")
    
    # Получаем порт из переменной окружения (для деплоя)
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)

