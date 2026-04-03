import json
import os
import requests
from requests.auth import HTTPBasicAuth
from PIL import Image

# ── 設定這裡 ──────────────────────────────────────────
BASE_URL   = 'https://aovsellwebsite-production.up.railway.app'
ADMIN_USER = 'crabstore'       # 改成你在 Railway 設的 ADMIN_USER
ADMIN_PASS = 'NNggininder@'    # 改成你在 Railway 設的 ADMIN_PASS
# ─────────────────────────────────────────────────────

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
IMG_DIR    = os.path.join(SCRIPT_DIR, 'acc_img')
IMG_EXTS   = {'.jpg', '.jpeg', '.png', '.gif', '.webp'}

auth = HTTPBasicAuth(ADMIN_USER, ADMIN_PASS)

# ══════════════════════════════════════════════════════
# 步驟 1：清空舊資料
# ══════════════════════════════════════════════════════
def clear_all():
    resp = requests.get(f'{BASE_URL}/api/accounts', auth=auth)
    accounts = resp.json()
    if not accounts:
        print('目前沒有舊資料，跳過清除。')
        return
    print(f'正在清除 {len(accounts)} 筆舊帳號...')
    for acc in accounts:
        requests.delete(f'{BASE_URL}/api/accounts/{acc["id"]}', auth=auth)
    print('✅ 清除完成\n')

# ══════════════════════════════════════════════════════
# 步驟 2：輸入每張圖的價格
# ══════════════════════════════════════════════════════
def collect_prices():
    files = sorted([
        f for f in os.listdir(IMG_DIR)
        if os.path.splitext(f)[1].lower() in IMG_EXTS
    ])

    if not files:
        print(f'❌ acc_img/ 資料夾裡沒有圖片，請先把圖片放進去。')
        return []

    print(f'找到 {len(files)} 張圖片，開始輸入價格。\n')
    print('（輸入價格後按 Enter；輸入 s 跳過此圖；輸入 q 中止）\n')

    orders = []
    for i, fname in enumerate(files, 1):
        img_path = os.path.join(IMG_DIR, fname)

        # 開啟系統看圖軟體
        try:
            img = Image.open(img_path)
            img.show()
        except Exception as e:
            print(f'  無法開啟圖片：{e}')

        while True:
            val = input(f'[{i}/{len(files)}] {fname} 價格 NT$: ').strip()
            if val.lower() == 'q':
                print('中止。')
                return []
            if val.lower() == 's':
                print(f'  跳過 {fname}')
                break
            if val.isdigit() and int(val) > 0:
                orders.append({'fname': fname, 'price': int(val)})
                break
            print('  請輸入正整數，或輸入 s 跳過、q 中止')

    return orders

# ══════════════════════════════════════════════════════
# 步驟 3：確認後上傳
# ══════════════════════════════════════════════════════
def upload_all(orders):
    print('\n── 確認清單 ──────────────────────────')
    for o in orders:
        print(f'  {o["fname"]:30s}  NT$ {o["price"]:,}')
    print(f'──────────────────────────────────────')
    print(f'共 {len(orders)} 筆，準備上傳。')

    confirm = input('\n確認上傳？(y/n): ').strip().lower()
    if confirm != 'y':
        print('取消。')
        return

    print()
    for i, o in enumerate(orders, 1):
        img_path = os.path.join(IMG_DIR, o['fname'])
        try:
            with open(img_path, 'rb') as f:
                resp = requests.post(
                    f'{BASE_URL}/api/accounts',
                    data={'price': str(o['price'])},
                    files={'image': (o['fname'], f)},
                    auth=auth
                )
            if resp.status_code == 201:
                print(f'[{i}/{len(orders)}] ✅ {o["fname"]}  NT$ {o["price"]:,}')
            else:
                print(f'[{i}/{len(orders)}] ❌ {o["fname"]} 失敗: {resp.status_code} {resp.text}')
        except Exception as e:
            print(f'[{i}/{len(orders)}] ❌ {o["fname"]} 錯誤: {e}')

    print('\n🎉 上傳完成！')

# ══════════════════════════════════════════════════════
if __name__ == '__main__':
    print('=== AOV 帳號每日上傳工具 ===\n')
    clear_all()
    orders = collect_prices()
    if orders:
        upload_all(orders)
