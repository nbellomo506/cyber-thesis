import ctypes
from ctypes import wintypes

class AMSIEngine:
    def __init__(self, app_name="MyEDR_Project"):
        self.amsi = None
        self.context = ctypes.c_void_p()
        self.app_name = app_name
        self._initialize()

    def _initialize(self):
        try:
            # Caricamento della DLL di sistema
            self.amsi = ctypes.windll.amsi
            
            # --- DEFINIZIONE RIGIDA DEI TIPI (ARGTYPES) ---
            # Questo assicura che Python passi i dati correttamente alla DLL Windows
            self.amsi.AmsiInitialize.argtypes = [ctypes.c_wchar_p, ctypes.POINTER(ctypes.c_void_p)]
            self.amsi.AmsiOpenSession.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
            self.amsi.AmsiScanBuffer.argtypes = [
                ctypes.c_void_p,       # hContext
                ctypes.c_void_p,       # buffer
                ctypes.c_ulong,        # length
                ctypes.c_wchar_p,      # contentName
                ctypes.c_void_p,       # amsiSession
                ctypes.POINTER(wintypes.DWORD) # pResult
            ]
            
            hr = self.amsi.AmsiInitialize(ctypes.c_wchar_p(self.app_name), ctypes.byref(self.context))
            if hr != 0:
                self.amsi = None
        except Exception as e:
            print(f"Errore inizializzazione AMSI: {e}")
            self.amsi = None

    def scan_string(self, content):
        """Restituisce il punteggio di pericolosità (32768 = Malware)"""
        if not self.amsi or not self.context or not content:
            return 0
        
        try:
            session = ctypes.c_void_p()
            self.amsi.AmsiOpenSession(self.context, ctypes.byref(session))
            
            result = wintypes.DWORD(0)
            # Windows richiede esplicitamente UTF-16 Little Endian
            content_b = content.encode('utf-16le')
            # Lunghezza calcolata in BYTE (fondamentale per non troncare la stringa)
            length_in_bytes = len(content_b)
            
            hr = self.amsi.AmsiScanBuffer(
                self.context, 
                content_b, 
                length_in_bytes,
                ctypes.c_wchar_p("Scanner"), 
                session, 
                ctypes.byref(result)
            )
            
            self.amsi.AmsiCloseSession(self.context, session)
            
            if hr == 0:
                return result.value
            return 0
        except Exception as e:
            print(f"Errore durante la scansione AMSI: {e}")
            return 0

    def __del__(self):
        if self.amsi and self.context:
            try:
                self.amsi.AmsiUninitialize(self.context)
            except:
                pass