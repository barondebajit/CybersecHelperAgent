import os
import json
import hashlib
import time
from datetime import datetime
from pathlib import Path
from google.genai import types

try:
    from PIL import Image
    from PIL.ExifTags import TAGS, GPSTAGS
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False

try:
    import pymupdf
    PYMUPDF_AVAILABLE = True
except ImportError:
    PYMUPDF_AVAILABLE = False

class MetadataExtractor:
    def __init__(self):
        self.supported_formats = {
            'image': ['.jpg', '.jpeg', '.png', '.tiff', '.tif', '.bmp', '.gif'],
            'pdf': ['.pdf'],
            'office': ['.docx', '.xlsx', '.pptx'],
            'text': ['.txt', '.log', '.csv'],
            'executable': ['.exe', '.dll', '.so'],
            'archive': ['.zip', '.rar', '.tar', '.gz']
        }

    def calculate_hashes(self, filepath):
        hashes = {}
        chunk_size = 8192
        
        hash_algorithms = {
            'md5': hashlib.md5(),
            'sha1': hashlib.sha1(),
            'sha256': hashlib.sha256(),
            'sha512': hashlib.sha512()
        }
        
        try:
            with open(filepath, 'rb') as f:
                while chunk := f.read(chunk_size):
                    for name, hasher in hash_algorithms.items():
                        hasher.update(chunk)
            
            for name, hasher in hash_algorithms.items():
                hashes[name] = hasher.hexdigest()
        except Exception as e:
            hashes['error'] = str(e)
        
        return hashes

    def get_basic_metadata(self, filepath):
        try:
            stat = os.stat(filepath)
            return {
                'filename': os.path.basename(filepath),
                'filepath': os.path.abspath(filepath),
                'size_bytes': stat.st_size,
                'size_human': self.format_size(stat.st_size),
                'created': datetime.fromtimestamp(stat.st_ctime).isoformat(),
                'modified': datetime.fromtimestamp(stat.st_mtime).isoformat(),
                'accessed': datetime.fromtimestamp(stat.st_atime).isoformat(),
                'permissions': oct(stat.st_mode)[-3:],
                'owner_uid': stat.st_uid,
                'group_gid': stat.st_gid
            }
        except Exception as e:
            return {'error': str(e)}

    def format_size(self, size_bytes):
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size_bytes < 1024.0:
                return f"{size_bytes:.2f} {unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.2f} PB"

    def extract_image_metadata(self, filepath):
        if not PIL_AVAILABLE:
            return {'error': 'PIL not available for image processing'}
        
        try:
            with Image.open(filepath) as img:
                metadata = {
                    'format': img.format,
                    'mode': img.mode,
                    'size': img.size,
                    'width': img.width,
                    'height': img.height,
                    'has_transparency': img.mode in ('RGBA', 'LA') or 'transparency' in img.info
                }
                
                if hasattr(img, '_getexif') and img._getexif():
                    exif_data = {}
                    exif = img._getexif()
                    
                    for tag_id, value in exif.items():
                        tag = TAGS.get(tag_id, tag_id)
                        
                        if tag == 'GPSInfo':
                            gps_data = {}
                            for gps_tag_id, gps_value in value.items():
                                gps_tag = GPSTAGS.get(gps_tag_id, gps_tag_id)
                                gps_data[gps_tag] = str(gps_value)
                            exif_data['GPS'] = gps_data
                        else:
                            exif_data[tag] = str(value)
                    
                    metadata['exif'] = exif_data
                
                return metadata
        except Exception as e:
            return {'error': str(e)}

    def extract_pdf_metadata(self, filepath):
        if not PYMUPDF_AVAILABLE:
            return self.extract_pdf_basic(filepath)
        
        try:
            doc = pymupdf.open(filepath)
            metadata = {
                'page_count': doc.page_count,
                'is_encrypted': doc.is_encrypted,
                'metadata': doc.metadata,
                'toc_items': len(doc.get_toc()),
                'has_links': False,
                'has_annotations': False,
                'text_pages': 0,
                'image_pages': 0
            }
            
            for page_num in range(min(doc.page_count, 10)):
                page = doc[page_num]
                if page.get_text().strip():
                    metadata['text_pages'] += 1
                if page.get_images():
                    metadata['image_pages'] += 1
                if page.get_links():
                    metadata['has_links'] = True
                if page.annots():
                    metadata['has_annotations'] = True
            
            doc.close()
            return metadata
        except Exception as e:
            return {'error': str(e)}

    def extract_pdf_basic(self, filepath):
        try:
            with open(filepath, 'rb') as f:
                content = f.read(1024)
                if b'%PDF' in content:
                    version_start = content.find(b'%PDF-') + 5
                    version_end = content.find(b'\n', version_start)
                    if version_end == -1:
                        version_end = version_start + 3
                    version = content[version_start:version_end].decode('ascii', errors='ignore')
                    
                    return {
                        'pdf_version': version,
                        'is_pdf': True,
                        'basic_scan': True
                    }
                else:
                    return {'error': 'Not a valid PDF file'}
        except Exception as e:
            return {'error': str(e)}

    def extract_text_metadata(self, filepath):
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                
            lines = content.split('\n')
            words = content.split()
            
            return {
                'encoding': 'utf-8',
                'line_count': len(lines),
                'word_count': len(words),
                'character_count': len(content),
                'character_count_no_spaces': len(content.replace(' ', '')),
                'empty_lines': sum(1 for line in lines if not line.strip()),
                'longest_line': max(len(line) for line in lines) if lines else 0,
                'average_line_length': sum(len(line) for line in lines) / len(lines) if lines else 0
            }
        except Exception as e:
            try:
                with open(filepath, 'rb') as f:
                    raw_content = f.read(1024)
                
                return {
                    'encoding': 'binary',
                    'sample_bytes': raw_content[:100].hex(),
                    'binary_file': True
                }
            except:
                return {'error': str(e)}

    def extract_executable_metadata(self, filepath):
        try:
            with open(filepath, 'rb') as f:
                header = f.read(1024)
            
            metadata = {
                'file_type': 'executable',
                'header_hex': header[:64].hex()
            }
            
            if header.startswith(b'MZ'):
                metadata['executable_type'] = 'PE (Windows)'
                if b'PE\x00\x00' in header:
                    metadata['pe_signature_found'] = True
            elif header.startswith(b'\x7fELF'):
                metadata['executable_type'] = 'ELF (Linux)'
                metadata['architecture'] = '64-bit' if header[4] == 2 else '32-bit'
            elif header.startswith(b'\xfe\xed\xfa'):
                metadata['executable_type'] = 'Mach-O (macOS)'
            else:
                metadata['executable_type'] = 'unknown'
            
            strings_found = []
            try:
                text_data = header.decode('ascii', errors='ignore')
                import re
                strings = re.findall(r'[A-Za-z0-9\s]{4,}', text_data)
                strings_found = strings[:10]
            except:
                pass
            
            metadata['readable_strings'] = strings_found
            return metadata
            
        except Exception as e:
            return {'error': str(e)}

    def detect_file_type(self, filepath):
        extension = Path(filepath).suffix.lower()
        
        for file_type, extensions in self.supported_formats.items():
            if extension in extensions:
                return file_type
        
        try:
            with open(filepath, 'rb') as f:
                header = f.read(16)
            
            signatures = {
                b'\xff\xd8\xff': 'image',
                b'\x89PNG': 'image', 
                b'GIF8': 'image',
                b'%PDF': 'pdf',
                b'PK\x03\x04': 'archive',
                b'MZ': 'executable',
                b'\x7fELF': 'executable'
            }
            
            for sig, file_type in signatures.items():
                if header.startswith(sig):
                    return file_type
                    
        except:
            pass
        
        return 'unknown'

    def extract_metadata(self, filepath, include_hashes=True, include_content=True):
        if not os.path.exists(filepath):
            return {'error': 'File not found'}
        
        metadata = {
            'extraction_time': datetime.now().isoformat(),
            'basic_info': self.get_basic_metadata(filepath)
        }
        
        if include_hashes:
            metadata['hashes'] = self.calculate_hashes(filepath)
        
        file_type = self.detect_file_type(filepath)
        metadata['detected_type'] = file_type
        
        if include_content:
            if file_type == 'image':
                metadata['image_metadata'] = self.extract_image_metadata(filepath)
            elif file_type == 'pdf':
                metadata['pdf_metadata'] = self.extract_pdf_metadata(filepath)
            elif file_type == 'text':
                metadata['text_metadata'] = self.extract_text_metadata(filepath)
            elif file_type == 'executable':
                metadata['executable_metadata'] = self.extract_executable_metadata(filepath)
        
        return metadata

    def extract_multiple(self, filepaths, include_hashes=True, include_content=True):
        results = {}
        
        for filepath in filepaths:
            results[filepath] = self.extract_metadata(filepath, include_hashes, include_content)
        
        return results

    def save_metadata(self, metadata, output_file):
        try:
            with open(output_file, 'w') as f:
                json.dump(metadata, f, indent=2, default=str)
            return True
        except Exception as e:
            return False

extractor = MetadataExtractor()

def extract_file_metadata(filepath, include_hashes=True, include_content=True):
    return extractor.extract_metadata(filepath, include_hashes, include_content)

def extract_multiple_files_metadata(filepaths, include_hashes=True, include_content=True):
    return extractor.extract_multiple(filepaths, include_hashes, include_content)

def calculate_file_hashes(filepath):
    return extractor.calculate_hashes(filepath)

def get_file_basic_info(filepath):
    return extractor.get_basic_metadata(filepath)

def detect_file_type_signature(filepath):
    return extractor.detect_file_type(filepath)

extract_metadata_function = types.FunctionDeclaration(
    name="extract_file_metadata",
    description="Extract comprehensive metadata from a file including hashes, basic info, and content-specific metadata",
    parameters=types.Schema(
        type=types.Type.OBJECT,
        properties={
            "filepath": types.Schema(
                type=types.Type.STRING,
                description="Path to the file to analyze"
            ),
            "include_hashes": types.Schema(
                type=types.Type.BOOLEAN,
                description="Whether to include hash calculations (MD5, SHA1, SHA256, SHA512)"
            ),
            "include_content": types.Schema(
                type=types.Type.BOOLEAN,
                description="Whether to include content-specific metadata (EXIF, PDF info, etc.)"
            )
        },
        required=["filepath"]
    )
)

extract_multiple_function = types.FunctionDeclaration(
    name="extract_multiple_files_metadata",
    description="Extract metadata from multiple files at once",
    parameters=types.Schema(
        type=types.Type.OBJECT,
        properties={
            "filepaths": types.Schema(
                type=types.Type.ARRAY,
                items=types.Schema(type=types.Type.STRING),
                description="List of file paths to analyze"
            ),
            "include_hashes": types.Schema(
                type=types.Type.BOOLEAN,
                description="Whether to include hash calculations for all files"
            ),
            "include_content": types.Schema(
                type=types.Type.BOOLEAN,
                description="Whether to include content-specific metadata for all files"
            )
        },
        required=["filepaths"]
    )
)

calculate_hashes_function = types.FunctionDeclaration(
    name="calculate_file_hashes",
    description="Calculate MD5, SHA1, SHA256, and SHA512 hashes for a file",
    parameters=types.Schema(
        type=types.Type.OBJECT,
        properties={
            "filepath": types.Schema(
                type=types.Type.STRING,
                description="Path to the file to hash"
            )
        },
        required=["filepath"]
    )
)

basic_info_function = types.FunctionDeclaration(
    name="get_file_basic_info",
    description="Get basic file information like size, timestamps, and permissions",
    parameters=types.Schema(
        type=types.Type.OBJECT,
        properties={
            "filepath": types.Schema(
                type=types.Type.STRING,
                description="Path to the file to analyze"
            )
        },
        required=["filepath"]
    )
)

detect_type_function = types.FunctionDeclaration(
    name="detect_file_type_signature",
    description="Detect file type based on extension and file signature/magic bytes",
    parameters=types.Schema(
        type=types.Type.OBJECT,
        properties={
            "filepath": types.Schema(
                type=types.Type.STRING,
                description="Path to the file to analyze"
            )
        },
        required=["filepath"]
    )
)