#!/usr/bin/env python3
"""
Fake Signature Module - модифицированная версия для веб-сервиса
Основано на оригинальном SigThief от secretsquirrel
"""

import sys
import struct
import shutil
import io
import os
import tempfile
from typing import Dict, Any, Optional, Tuple


class FakeSignatureError(Exception):
    """Исключение для ошибок Fake Signature"""
    pass


class FakeSignature:
    """Класс для работы с цифровыми подписями PE файлов"""
    
    def __init__(self):
        pass
    
    def gather_file_info_win(self, binary_path: str) -> Dict[str, Any]:
        """
        Анализирует PE структуру файла
        Возвращает словарь с информацией о файле
        """
        flItms = {}
        
        try:
            with open(binary_path, 'rb') as binary:
                binary.seek(int('3C', 16))
                flItms['buffer'] = 0
                flItms['JMPtoCodeAddress'] = 0
                flItms['dis_frm_pehdrs_sectble'] = 248
                flItms['pe_header_location'] = struct.unpack('<i', binary.read(4))[0]
                
                # Start of COFF
                flItms['COFF_Start'] = flItms['pe_header_location'] + 4
                binary.seek(flItms['COFF_Start'])
                flItms['MachineType'] = struct.unpack('<H', binary.read(2))[0]
                binary.seek(flItms['COFF_Start'] + 2, 0)
                flItms['NumberOfSections'] = struct.unpack('<H', binary.read(2))[0]
                flItms['TimeDateStamp'] = struct.unpack('<I', binary.read(4))[0]
                binary.seek(flItms['COFF_Start'] + 16, 0)
                flItms['SizeOfOptionalHeader'] = struct.unpack('<H', binary.read(2))[0]
                flItms['Characteristics'] = struct.unpack('<H', binary.read(2))[0]
                
                # End of COFF
                flItms['OptionalHeader_start'] = flItms['COFF_Start'] + 20
                
                # Begin Standard Fields section of Optional Header
                binary.seek(flItms['OptionalHeader_start'])
                flItms['Magic'] = struct.unpack('<H', binary.read(2))[0]
                flItms['MajorLinkerVersion'] = struct.unpack("!B", binary.read(1))[0]
                flItms['MinorLinkerVersion'] = struct.unpack("!B", binary.read(1))[0]
                flItms['SizeOfCode'] = struct.unpack("<I", binary.read(4))[0]
                flItms['SizeOfInitializedData'] = struct.unpack("<I", binary.read(4))[0]
                flItms['SizeOfUninitializedData'] = struct.unpack("<I", binary.read(4))[0]
                flItms['AddressOfEntryPoint'] = struct.unpack('<I', binary.read(4))[0]
                flItms['PatchLocation'] = flItms['AddressOfEntryPoint']
                flItms['BaseOfCode'] = struct.unpack('<I', binary.read(4))[0]
                
                if flItms['Magic'] != 0x20B:
                    flItms['BaseOfData'] = struct.unpack('<I', binary.read(4))[0]
                
                # Begin Windows-Specific Fields of Optional Header
                if flItms['Magic'] == 0x20B:
                    flItms['ImageBase'] = struct.unpack('<Q', binary.read(8))[0]
                else:
                    flItms['ImageBase'] = struct.unpack('<I', binary.read(4))[0]
                
                flItms['SectionAlignment'] = struct.unpack('<I', binary.read(4))[0]
                flItms['FileAlignment'] = struct.unpack('<I', binary.read(4))[0]
                flItms['MajorOperatingSystemVersion'] = struct.unpack('<H', binary.read(2))[0]
                flItms['MinorOperatingSystemVersion'] = struct.unpack('<H', binary.read(2))[0]
                flItms['MajorImageVersion'] = struct.unpack('<H', binary.read(2))[0]
                flItms['MinorImageVersion'] = struct.unpack('<H', binary.read(2))[0]
                flItms['MajorSubsystemVersion'] = struct.unpack('<H', binary.read(2))[0]
                flItms['MinorSubsystemVersion'] = struct.unpack('<H', binary.read(2))[0]
                flItms['Win32VersionValue'] = struct.unpack('<I', binary.read(4))[0]
                flItms['SizeOfImageLoc'] = binary.tell()
                flItms['SizeOfImage'] = struct.unpack('<I', binary.read(4))[0]
                flItms['SizeOfHeaders'] = struct.unpack('<I', binary.read(4))[0]
                flItms['CheckSum'] = struct.unpack('<I', binary.read(4))[0]
                flItms['Subsystem'] = struct.unpack('<H', binary.read(2))[0]
                flItms['DllCharacteristics'] = struct.unpack('<H', binary.read(2))[0]
                
                if flItms['Magic'] == 0x20B:
                    flItms['SizeOfStackReserve'] = struct.unpack('<Q', binary.read(8))[0]
                    flItms['SizeOfStackCommit'] = struct.unpack('<Q', binary.read(8))[0]
                    flItms['SizeOfHeapReserve'] = struct.unpack('<Q', binary.read(8))[0]
                    flItms['SizeOfHeapCommit'] = struct.unpack('<Q', binary.read(8))[0]
                else:
                    flItms['SizeOfStackReserve'] = struct.unpack('<I', binary.read(4))[0]
                    flItms['SizeOfStackCommit'] = struct.unpack('<I', binary.read(4))[0]
                    flItms['SizeOfHeapReserve'] = struct.unpack('<I', binary.read(4))[0]
                    flItms['SizeOfHeapCommit'] = struct.unpack('<I', binary.read(4))[0]
                
                flItms['LoaderFlags'] = struct.unpack('<I', binary.read(4))[0]
                flItms['NumberofRvaAndSizes'] = struct.unpack('<I', binary.read(4))[0]
                
                # Begin Data Directories of Optional Header
                flItms['ExportTableRVA'] = struct.unpack('<I', binary.read(4))[0]
                flItms['ExportTableSize'] = struct.unpack('<I', binary.read(4))[0]
                flItms['ImportTableLOCInPEOptHdrs'] = binary.tell()
                flItms['ImportTableRVA'] = struct.unpack('<I', binary.read(4))[0]
                flItms['ImportTableSize'] = struct.unpack('<I', binary.read(4))[0]
                flItms['ResourceTable'] = struct.unpack('<Q', binary.read(8))[0]
                flItms['ExceptionTable'] = struct.unpack('<Q', binary.read(8))[0]
                flItms['CertTableLOC'] = binary.tell()
                flItms['CertLOC'] = struct.unpack("<I", binary.read(4))[0]
                flItms['CertSize'] = struct.unpack("<I", binary.read(4))[0]
                
        except Exception as e:
            raise FakeSignatureError(f"Ошибка анализа PE файла: {str(e)}")
        
        return flItms
    
    def copy_cert(self, exe_path: str) -> bytes:
        """
        Извлекает сертификат из подписанного файла
        """
        flItms = self.gather_file_info_win(exe_path)
        
        if flItms['CertLOC'] == 0 or flItms['CertSize'] == 0:
            raise FakeSignatureError("Входной файл не подписан!")
        
        try:
            with open(exe_path, 'rb') as f:
                f.seek(flItms['CertLOC'], 0)
                cert = f.read(flItms['CertSize'])
                return cert
        except Exception as e:
            raise FakeSignatureError(f"Ошибка извлечения сертификата: {str(e)}")
    
    def write_cert(self, cert: bytes, exe_path: str, output_path: str) -> str:
        """
        Записывает сертификат в целевой файл
        """
        try:
            flItms = self.gather_file_info_win(exe_path)
            
            # Копируем исходный файл
            shutil.copy2(exe_path, output_path)
            
            with open(exe_path, 'rb') as g:
                with open(output_path, 'wb') as f:
                    f.write(g.read())
                    f.seek(0)
                    f.seek(flItms['CertTableLOC'], 0)
                    f.write(struct.pack("<I", len(open(exe_path, 'rb').read())))
                    f.write(struct.pack("<I", len(cert)))
                    f.seek(0, io.SEEK_END)
                    f.write(cert)
            
            return output_path
            
        except Exception as e:
            raise FakeSignatureError(f"Ошибка записи сертификата: {str(e)}")
    
    def check_signature(self, exe_path: str) -> bool:
        """
        Проверяет наличие подписи в файле (не валидность)
        """
        try:
            flItms = self.gather_file_info_win(exe_path)
            return not (flItms['CertLOC'] == 0 or flItms['CertSize'] == 0)
        except:
            return False
    
    def process_files(self, signed_file_path: str, target_file_path: str, output_path: str) -> Tuple[str, str]:
        """
        Основная функция для копирования подписи между файлами
        Возвращает путь к результирующему файлу и имя файла
        """
        try:
            # Проверяем, что исходный файл подписан
            if not self.check_signature(signed_file_path):
                raise FakeSignatureError("Исходный файл не содержит цифровой подписи")
            
            # Извлекаем сертификат
            cert = self.copy_cert(signed_file_path)
            
            # Записываем сертификат в целевой файл
            result_path = self.write_cert(cert, target_file_path, output_path)
            
            # Получаем имя файла
            filename = os.path.basename(result_path)
            
            return result_path, filename
            
        except FakeSignatureError:
            raise
        except Exception as e:
            raise FakeSignatureError(f"Неожиданная ошибка: {str(e)}")


# Функция для создания экземпляра
def create_fake_signature() -> FakeSignature:
    """Создает и возвращает экземпляр FakeSignature"""
    return FakeSignature()

