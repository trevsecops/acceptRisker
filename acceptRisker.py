import csv
import logging
from tenable.sc import TenableSC

# -----------------------------------------------------------------------------
# LOGGING CONFIGURATION
# -----------------------------------------------------------------------------
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("asset_creation.log"),   # detailed log file
        logging.StreamHandler()                      # console output
    ]
)

# -----------------------------------------------------------------------------
# TENABLE.SC CONNECTION
# -----------------------------------------------------------------------------
a_key = "078f9ac50b734a0b89c3558fc398ab90"
s_key = "79ace1cc876f4870b43d34c24cee9984"
tenable_sc_url = "tenable_admin.sce.com"

logging.info("Connecting to Tenable.sc...")
sc = TenableSC(tenable_sc_url)
sc.login(access_key=a_key, secret_key=s_key)
logging.info("Connected successfully.")

plugins = sc.plugins.list(filter=('name', 'like', 'Linux Distros Unpatched Vulnerability'))
for plugin in plugins:
    print(plugin)
