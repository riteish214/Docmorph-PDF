document.addEventListener('DOMContentLoaded', function() {
    const dropZone = document.getElementById('dropZone');
    const fileInput = document.getElementById('fileInput');
    
    if (dropZone && fileInput) {
        dropZone.addEventListener('click', () => fileInput.click());
        
        dropZone.addEventListener('dragover', (e) => {
            e.preventDefault();
            dropZone.classList.add('dragover');
        });
        
        dropZone.addEventListener('dragleave', () => {
            dropZone.classList.remove('dragover');
        });
        
        dropZone.addEventListener('drop', (e) => {
            e.preventDefault();
            dropZone.classList.remove('dragover');
            
            if (e.dataTransfer.files.length > 0) {
                fileInput.files = e.dataTransfer.files;
                updateFileList();
            }
        });
        
        fileInput.addEventListener('change', updateFileList);
    }
});

function updateFileList() {
    const fileInput = document.getElementById('fileInput');
    const fileList = document.getElementById('fileList');
    
    if (!fileList) return;
    
    fileList.innerHTML = '';
    
    if (fileInput.files.length > 0) {
        fileList.style.display = 'block';
        
        for (let i = 0; i < fileInput.files.length; i++) {
            const file = fileInput.files[i];
            const fileItem = document.createElement('div');
            fileItem.className = 'file-item';
            
            const fileName = document.createElement('span');
            fileName.textContent = file.name;
            
            const fileSize = document.createElement('span');
            fileSize.className = 'text-muted';
            fileSize.textContent = formatFileSize(file.size);
            
            fileItem.appendChild(fileName);
            fileItem.appendChild(fileSize);
            fileList.appendChild(fileItem);
        }
    } else {
        fileList.style.display = 'none';
    }
}

function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    
    return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
}

function showProgress(show) {
    const progressBar = document.getElementById('progressBar');
    if (progressBar) {
        if (show) {
            progressBar.classList.remove('d-none');
            progressBar.querySelector('.progress-bar').style.width = '100%';
        } else {
            progressBar.classList.add('d-none');
        }
    }
}

function showResult(message, type) {
    const result = document.getElementById('result');
    if (result) {
        result.className = `alert alert-${type}`;
        result.innerHTML = message;
        result.classList.remove('d-none');
        
        setTimeout(() => {
            result.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
        }, 100);
    }
}
