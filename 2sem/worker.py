from celery import Celery
import os
import subprocess
import time
import logging
from typing import Optional
from datetime import datetime
import itertools
import hashlib

# Настройка логирования
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Инициализация Celery
celery_app = Celery('tasks', broker='redis://localhost:6379/0', backend='redis://localhost:6379/0')
celery_app.conf.broker_connection_retry_on_startup = True

def save_password_to_file(file_path: str, password: str, attempts: int, elapsed_time: float):
    """Сохранение найденного пароля в файл"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    result_dir = "cracked_passwords"
    
    # Создаем директорию, если она не существует
    if not os.path.exists(result_dir):
        os.makedirs(result_dir)
    
    # Получаем хеш архива
    archive_hash = get_file_hash(file_path)
    
    # Формируем имя файла на основе хеша архива
    result_file = os.path.join(result_dir, f"{archive_hash}_password.txt")
    
    # Записываем информацию о найденном пароле
    with open(result_file, "w", encoding="utf-8") as f:
        f.write(f"Дата и время: {timestamp}\n")
        f.write(f"Хеш архива: {archive_hash}\n")
        f.write(f"Пароль: {password}\n")
        f.write(f"Количество попыток: {attempts}\n")
        f.write(f"Время перебора: {elapsed_time:.2f} сек\n")
        f.write("-" * 50 + "\n")
    
    logger.info(f"Пароль сохранен в файл: {result_file}")

def get_file_hash(file_path: str) -> str:
    """Вычисляет SHA-256 хеш файла"""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def generate_password_batch(length: int, charset: str, batch_size: int = 1000):
    """Генерирует пароли указанной длины пакетами для экономии памяти."""
    chars = list(charset)
    batch = []
    
    for combination in itertools.product(chars, repeat=length):
        password = ''.join(combination)
        batch.append(password)
        
        if len(batch) >= batch_size:
            yield batch
            batch = []
    
    if batch:  # Возвращаем оставшиеся пароли
        yield batch

@celery_app.task(bind=True)
def bruteforce_rar(self, file_path: str, min_length: int = 4, max_length: int = 8, 
                   charset: Optional[str] = None, max_attempts: Optional[int] = None) -> dict:
    """Перебор паролей для RAR архива."""
    if charset is None:
        charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    
    logger.info(f"Начало перебора паролей для файла: {file_path}")
    
    if not os.path.exists(file_path):
        logger.error(f"Файл не найден: {file_path}")
        return {"status": "error", "message": "Файл не найден"}
    
    # Получаем хеш архива
    archive_hash = get_file_hash(file_path)
    logger.info(f"Хеш архива: {archive_hash}")
    
    start_time = time.time()
    attempts = 0
    batch_size = 1000
    
    # Создаем временную директорию для распаковки
    temp_dir = os.path.join(os.path.dirname(file_path), "temp_extract")
    if not os.path.exists(temp_dir):
        os.makedirs(temp_dir)
    
    try:
        for length in range(min_length, max_length + 1):
            logger.info(f"Перебор паролей длины {length}")
            
            for password_batch in generate_password_batch(length, charset, batch_size):
                for password in password_batch:
                    if max_attempts and attempts >= max_attempts:
                        logger.info(f"Достигнут лимит попыток: {max_attempts}")
                        return {
                            "status": "stopped",
                            "attempts": attempts,
                            "elapsed_time": time.time() - start_time
                        }
                    
                    attempts += 1
                    if attempts % 100 == 0:  # Обновляем каждые 100 попыток
                        try:
                            logger.info(f"Попыток: {attempts}, текущий пароль: {password}")
                            self.update_state(state='PROGRESS', 
                                            meta={'attempts': attempts, 
                                                 'rate': attempts / (time.time() - start_time)})
                        except Exception as e:
                            logger.error(f"Ошибка обновления состояния: {str(e)}")
                    
                    try:
                        # Очищаем временную директорию перед каждой попыткой
                        for file in os.listdir(temp_dir):
                            os.remove(os.path.join(temp_dir, file))
                        
                        # Пытаемся распаковать архив во временную директорию
                        result = subprocess.run(['unar', '-p', password, '-o', temp_dir, file_path], 
                                             capture_output=True, text=True)
                        
                        if result.returncode == 0:
                            # Проверяем, что файлы действительно распаковались
                            extracted_files = os.listdir(temp_dir)
                            if extracted_files:
                                elapsed_time = time.time() - start_time
                                logger.info(f"Пароль найден: {password}")
                                
                                # Сохраняем пароль только при успешном подборе
                                save_password_to_file(file_path, password, attempts, elapsed_time)
                                
                                # Очищаем временную директорию
                                for file in extracted_files:
                                    os.remove(os.path.join(temp_dir, file))
                                os.rmdir(temp_dir)
                                
                                return {
                                    "status": "success",
                                    "password": password,
                                    "attempts": attempts,
                                    "elapsed_time": elapsed_time,
                                    "archive_hash": archive_hash
                                }
                            
                    except Exception as e:
                        logger.error(f"Ошибка при попытке распаковать архив: {str(e)}")
                        continue
                        
    except Exception as e:
        logger.error(f"Критическая ошибка: {str(e)}")
        return {
            "status": "error",
            "message": str(e),
            "attempts": attempts,
            "elapsed_time": time.time() - start_time
        }
    finally:
        # Очищаем временную директорию в любом случае
        if os.path.exists(temp_dir):
            for file in os.listdir(temp_dir):
                os.remove(os.path.join(temp_dir, file))
            os.rmdir(temp_dir)
    
    elapsed_time = time.time() - start_time
    logger.info(f"Пароль не найден после {attempts} попыток")
    return {
        "status": "failed",
        "attempts": attempts,
        "elapsed_time": elapsed_time
    } 