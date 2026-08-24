document.addEventListener('DOMContentLoaded', () => {
    // Navigation
    document.querySelectorAll('.nav-btn').forEach(btn => {
        btn.addEventListener('click', (e) => {
            document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
            document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
            
            e.target.classList.add('active');
            const targetId = e.target.getAttribute('data-target');
            document.getElementById(targetId).classList.add('active');
        });
    });

    // Helper to format bytes
    function formatBytes(bytes, decimals = 2) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const dm = decimals < 0 ? 0 : decimals;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
    }

    // Drag and drop helper
    function setupDropZone(dropZoneId, inputId, onFileSelected) {
        const dropZone = document.getElementById(dropZoneId);
        const input = document.getElementById(inputId);

        dropZone.addEventListener('click', () => input.click());
        input.addEventListener('change', () => {
            if (input.files.length) onFileSelected(input.files[0]);
        });

        dropZone.addEventListener('dragover', (e) => {
            e.preventDefault();
            dropZone.classList.add('dragover');
        });

        dropZone.addEventListener('dragleave', () => dropZone.classList.remove('dragover'));

        dropZone.addEventListener('drop', (e) => {
            e.preventDefault();
            dropZone.classList.remove('dragover');
            if (e.dataTransfer.files.length) onFileSelected(e.dataTransfer.files[0]);
        });
    }

    // CREATE VIEW
    let createSelectedFile = null;
    setupDropZone('create-drop-zone', 'create-file-input', (file) => {
        createSelectedFile = file;
        const info = document.getElementById('create-file-info');
        info.innerHTML = `<div>${file.name}</div><div>${formatBytes(file.size)}</div>`;
        info.classList.remove('hidden');
        document.getElementById('convert-btn').disabled = false;
    });

    document.getElementById('convert-btn').addEventListener('click', async () => {
        if (!createSelectedFile) return;
        
        const sign = document.getElementById('sign-checkbox').checked;
        const formData = new FormData();
        formData.append('file', createSelectedFile);
        formData.append('sign', sign);

        const res = await fetch('/api/convert', { method: 'POST', body: formData });
        if (res.ok) {
            const blob = await res.blob();
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            let outName = createSelectedFile.name;
            const lastDot = outName.lastIndexOf('.');
            if(lastDot > -1) outName = outName.substring(0, lastDot);
            a.download = outName + '.stmf';
            a.click();
            
            const resultDiv = document.getElementById('create-result');
            resultDiv.innerHTML = `✓ STM Container Created<br>Original File: ${createSelectedFile.name}<br>Signature: ${sign ? 'Enabled' : 'Disabled'}`;
            resultDiv.classList.remove('hidden');
        } else {
            alert('Failed to convert file');
        }
    });

    // OPEN VIEW
    let currentOpenStmf = null;
    let currentObjectNumber = null;
    
    setupDropZone('open-drop-zone', 'open-file-input', async (file) => {
        currentOpenStmf = file;
        const formData = new FormData();
        formData.append('file', file);
        
        const res = await fetch('/api/open', { method: 'POST', body: formData });
        const data = await res.json();
        
        const container = document.getElementById('viewer-container');
        container.classList.remove('hidden');
        
        const statusDiv = document.getElementById('security-status');
        let statusHtml = `
            <div class="status-item ${data.valid ? 'valid' : 'invalid'}">
                ${data.valid ? '✓ Container Valid' : '✗ Container Invalid'}
            </div>
            <div class="status-item ${data.merkle_valid ? 'valid' : 'invalid'}">
                ${data.merkle_valid ? '✓ Merkle Integrity Valid' : '✗ Merkle Root Mismatch'}
            </div>
        `;
        
        if (data.signed) {
            const sigValid = data.signature_valid;
            statusHtml += `
                <div class="status-item ${sigValid ? 'valid' : 'invalid'}">
                    ${sigValid ? '✓ Digital Signature Valid' : '✗ Digital Signature Invalid'}
                </div>
            `;
        } else {
            statusHtml += `<div class="status-item valid">○ Not Signed</div>`;
        }
        statusDiv.innerHTML = statusHtml;

        const previewDiv = document.getElementById('media-preview');
        previewDiv.innerHTML = ''; // clear
        
        if (!data.valid) {
            previewDiv.innerHTML = '<div style="color:var(--error)">Cannot preview untrusted container.</div>';
            return;
        }
        
        if (data.files && data.files.length > 0) {
            const fileMeta = data.files[0];
            currentObjectNumber = fileMeta.file_object_number || fileMeta.object_number || 1;
            
            // fetch preview
            const previewForm = new FormData();
            previewForm.append('file', currentOpenStmf);
            previewForm.append('object_number', currentObjectNumber);
            
            const pRes = await fetch('/api/preview', { method: 'POST', body: previewForm });
            if (!pRes.ok) {
                const errText = await pRes.text();
                previewDiv.innerHTML = `<div>Failed to load preview: ${errText}</div>`;
                return;
            }
            
            const pBlob = await pRes.blob();
            const url = URL.createObjectURL(pBlob);
            
            const mime = (fileMeta.mime_type || pBlob.type || '').toLowerCase();
            
            if (mime.startsWith('image/')) {
                previewDiv.innerHTML = `<img src="${url}" alt="${fileMeta.filename || 'Preview'}">`;
            } else if (mime.startsWith('video/')) {
                previewDiv.innerHTML = `<video src="${url}" controls autoplay></video>`;
            } else if (mime.startsWith('audio/')) {
                previewDiv.innerHTML = `<audio src="${url}" controls autoplay></audio>`;
            } else if (mime === 'application/pdf') {
                previewDiv.innerHTML = `<iframe src="${url}"></iframe>`;
            } else if (mime.startsWith('text/') || mime === 'application/json') {
                const text = await pBlob.text();
                previewDiv.innerHTML = `<pre>${text}</pre>`;
            } else {
                previewDiv.innerHTML = `<div>No preview available for ${mime} (${formatBytes(pBlob.size)})</div>`;
            }
        } else {
            // Fallback for containers without metadata: preview object 1
            currentObjectNumber = 1;
            const previewForm = new FormData();
            previewForm.append('file', currentOpenStmf);
            previewForm.append('object_number', 1);
            const pRes = await fetch('/api/preview', { method: 'POST', body: previewForm });
            if (pRes.ok) {
                const pBlob = await pRes.blob();
                const url = URL.createObjectURL(pBlob);
                const mime = (pBlob.type || '').toLowerCase();
                if (mime.startsWith('image/')) {
                    previewDiv.innerHTML = `<img src="${url}" alt="Preview">`;
                } else if (mime.startsWith('video/')) {
                    previewDiv.innerHTML = `<video src="${url}" controls></video>`;
                } else if (mime.startsWith('audio/')) {
                    previewDiv.innerHTML = `<audio src="${url}" controls></audio>`;
                } else if (mime === 'application/pdf') {
                    previewDiv.innerHTML = `<iframe src="${url}"></iframe>`;
                } else if (mime.startsWith('text/') || mime === 'application/json') {
                    const text = await pBlob.text();
                    previewDiv.innerHTML = `<pre>${text}</pre>`;
                } else {
                    previewDiv.innerHTML = `<div>Extracted object 1 (${formatBytes(pBlob.size)})</div>`;
                }
            }
        }
    });
    
    document.getElementById('extract-btn').addEventListener('click', async () => {
        if (!currentOpenStmf || currentObjectNumber === null) return;
        const formData = new FormData();
        formData.append('file', currentOpenStmf);
        formData.append('object_number', currentObjectNumber);
        
        const res = await fetch('/api/extract', { method: 'POST', body: formData });
        if (res.ok) {
            const blob = await res.blob();
            let filename = "extracted";
            
            // try to get filename from headers
            const disp = res.headers.get('Content-Disposition');
            if (disp && disp.includes('filename="')) {
                filename = disp.split('filename="')[1].split('"')[0];
            }
            
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = filename;
            a.click();
        }
    });

    // VERIFY VIEW
    setupDropZone('verify-drop-zone', 'verify-file-input', async (file) => {
        const formData = new FormData();
        formData.append('file', file);
        const res = await fetch('/api/verify', { method: 'POST', body: formData });
        const data = await res.json();
        
        const resultDiv = document.getElementById('verify-result');
        let html = `
            <div class="status-item ${data.valid ? 'valid' : 'invalid'}">
                ${data.valid ? '✓ Container Valid' : '✗ Container Invalid'}
            </div>
            <div class="status-item ${data.merkle_valid ? 'valid' : 'invalid'}">
                ${data.merkle_valid ? '✓ Merkle Integrity Valid' : '✗ Merkle Root Mismatch'}
            </div>
        `;
        if (data.signed) {
            const sigValid = data.signature_valid;
            html += `
                <div class="status-item ${sigValid ? 'valid' : 'invalid'}">
                    ${sigValid ? '✓ Digital Signature Valid' : '✗ Digital Signature Invalid'}
                </div>
            `;
        } else {
            html += `<div class="status-item valid">○ Not Signed</div>`;
        }
        
        resultDiv.innerHTML = html;
        resultDiv.classList.remove('hidden');
    });

    // INSPECT VIEW
    setupDropZone('inspect-drop-zone', 'inspect-file-input', async (file) => {
        const formData = new FormData();
        formData.append('file', file);
        const res = await fetch('/api/inspect', { method: 'POST', body: formData });
        const data = await res.json();
        
        const resultDiv = document.getElementById('inspect-result');
        if (data.error) {
            resultDiv.innerHTML = `<div style="color:var(--error)">Error inspecting file: ${data.error}</div>`;
            resultDiv.classList.remove('hidden');
            return;
        }

        let metaHtml = '';
        if (data.metadata) {
            metaHtml = `
                <div style="margin-top:12px; padding:12px; background:rgba(255,255,255,0.03); border-radius:6px;">
                    <strong>Embedded File Metadata</strong><br>
                    Filename: <code>${data.metadata.filename}</code><br>
                    MIME Type: <code>${data.metadata.mime_type}</code><br>
                    Original Size: ${formatBytes(data.metadata.size)}<br>
                    File Object #: ${data.metadata.file_object_number}
                </div>
            `;
        }

        let objectsHtml = data.objects.map((obj, i) => `
            <div style="margin-top:8px; padding:8px; background:rgba(0,0,0,0.2); border-radius:4px; font-size:0.85rem;">
                <strong>Object #${i}</strong> | Type: ${obj.obj_type === 1 ? 'METADATA' : (obj.obj_type === 2 ? 'FILE' : obj.obj_type)} | Size: ${formatBytes(obj.length)} | Offset: ${obj.offset} bytes
            </div>
        `).join('');

        let html = `
            <div style="line-height:1.6;">
                <strong>Total Size:</strong> ${formatBytes(data.total_length)}<br>
                <strong>Object Count:</strong> ${data.object_count}<br>
                <strong>Signed:</strong> ${data.signed ? 'YES' : 'NO'}<br>
                <strong>Signature Status:</strong> ${data.signed ? (data.signature_valid ? '<span style="color:var(--success)">VALID</span>' : '<span style="color:var(--error)">INVALID</span>') : 'NOT PRESENT'}<br>
                <strong>Merkle Integrity:</strong> ${data.merkle_valid ? '<span style="color:var(--success)">VALID</span>' : '<span style="color:var(--error)">INVALID</span>'}<br>
                <strong>Merkle Root:</strong> <code style="word-break:break-all; font-size:0.8rem;">${data.merkle_root}</code>
                ${metaHtml}
                <div style="margin-top:16px;">
                    <strong>Container Objects:</strong>
                    ${objectsHtml}
                </div>
            </div>
        `;
        resultDiv.innerHTML = html;
        resultDiv.classList.remove('hidden');
    });
});
