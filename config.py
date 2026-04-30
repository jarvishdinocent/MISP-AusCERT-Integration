cp config.py.example config.py
    ```
2.  **Edit `config.py`** with your MISP instance details:
    
```python
    MISP_URL = "[https://your-misp-instance.com](https://your-misp-instance.com)"
    MISP_KEY = "YOUR_API_KEY_HERE"
    VERIFY_SSL = False  # Set to True if using valid CA certificates
    ```

---

## 🚀 Usage

### Manual Execution
To trigger a manual sync and pull the latest advisories:
```bash
python3 ingestor.py
