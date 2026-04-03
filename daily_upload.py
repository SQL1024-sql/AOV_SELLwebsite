import json
import os
import re
import requests
from requests.auth import HTTPBasicAuth
from PIL import Image

# ── 設定從環境變數讀取（不要把密碼寫在程式碼裡）────────
BASE_URL   = os.environ.get('SITE_URL',    'https://aovsellwebsite-production.up.railway.app')
ADMIN_USER = os.environ.get('ADMIN_USER')
ADMIN_PASS = os.environ.get('ADMIN_PASS')
if not ADMIN_USER or not ADMIN_PASS:
    raise SystemExit('❌ 請先設定環境變數 ADMIN_USER 和 ADMIN_PASS，例如：\n'
                     '   export ADMIN_USER=你的帳號\n'
                     '   export ADMIN_PASS=你的密碼')
# ─────────────────────────────────────────────────────

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
IMG_DIR    = os.path.join(SCRIPT_DIR, 'acc_img')
IMG_EXTS   = {'.jpg', '.jpeg', '.png', '.gif', '.webp'}

auth = HTTPBasicAuth(ADMIN_USER, ADMIN_PASS)

# ══════════════════════════════════════════════════════
# OCR 辨識價格（PaddleOCR PP-OCRv4）
# ══════════════════════════════════════════════════════
try:
    from paddleocr import PaddleOCR
    _ocr = PaddleOCR(use_angle_cls=True, lang='ch', show_log=False)
    OCR_AVAILABLE = True
except ImportError:
    OCR_AVAILABLE = False


def parse_price_value(raw: str) -> int | None:
    """
    將數字字串轉成 NT$ 整數。
    有小數點：整數部分 × 10000 + 小數部分 × 1000
      例：1.2 → 12000，5.3 → 53000
    無小數點：直接取整數
    """
    raw = raw.strip()
    try:
        if '.' in raw:
            integer_part, decimal_part = raw.split('.', 1)
            decimal_part = (decimal_part + '0')[:1]
            return int(integer_part) * 10000 + int(decimal_part) * 1000
        else:
            return int(raw)
    except ValueError:
        return None


def _pick_best_price(candidates: list[str]) -> int | None:
    """
    從 OCR 辨識出的所有文字中挑選最像價格的數字。
    優先順序：
      1. 帶小數點的數字（如 1.2、5.3）→ 萬元格式
      2. 3~6 位整數（直接當 NT$ 金額）
    回傳轉換後的整數，找不到回傳 None。
    """
    decimal_pat = re.compile(r'\b(\d{1,2}\.\d)\b')
    integer_pat = re.compile(r'\b(\d{3,6})\b')

    # 優先找小數格式
    for text in candidates:
        m = decimal_pat.search(text)
        if m:
            return parse_price_value(m.group(1))

    # 再找整數格式
    for text in candidates:
        m = integer_pat.search(text)
        if m:
            return parse_price_value(m.group(1))

    return None


def recognize_price_with_ocr(img_path: str) -> int | None:
    """用 PaddleOCR 辨識圖片中的價格，回傳 NT$ 整數。"""
    if not OCR_AVAILABLE:
        return None
    try:
        result = _ocr.ocr(img_path, cls=True)
        if not result or not result[0]:
            return None
        # result[0] = [ [bbox, [text, confidence]], ... ]
        texts = [line[1][0] for line in result[0] if line[1][1] > 0.5]
        return _pick_best_price(texts)
    except Exception as e:
        print(f'  ⚠️  OCR 辨識失敗：{e}')
        return None


def recognize_price(img_path: str) -> tuple[int | None, str]:
    """辨識價格，回傳 (價格, 來源)。"""
    if OCR_AVAILABLE:
        price = recognize_price_with_ocr(img_path)
        if price:
            return price, 'OCR'
    return None, ''


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

    auto_available = OCR_AVAILABLE
    if auto_available:
        print(f'找到 {len(files)} 張圖片，使用 PaddleOCR 自動辨識價格。\n')
        print('（直接按 Enter 採用辨識結果；輸入新數字覆蓋；輸入 s 跳過；輸入 q 中止）\n')
        print('價格規則：有小數點的 1 代表 10000（例：1.2→12000，5.3→53000）\n')
    else:
        print(f'找到 {len(files)} 張圖片，開始輸入價格。\n')
        print('（輸入價格後按 Enter；輸入 s 跳過此圖；輸入 q 中止）\n')
        print('（提示：pip install paddleocr paddlepaddle 可啟用自動辨識）\n')

    orders = []
    for i, fname in enumerate(files, 1):
        img_path = os.path.join(IMG_DIR, fname)

        # 開啟系統看圖軟體
        try:
            img = Image.open(img_path)
            img.show()
        except Exception as e:
            print(f'  無法開啟圖片：{e}')

        # 自動辨識（本地 OCR → 雲端備援）
        ai_price = None
        if auto_available:
            print(f'[{i}/{len(files)}] {fname}  ⏳ 辨識中...', end='', flush=True)
            ai_price, source = recognize_price(img_path)
            if ai_price:
                print(f'\r[{i}/{len(files)}] {fname}  [{source}] NT$ {ai_price:,}')
            else:
                print(f'\r[{i}/{len(files)}] {fname}  ⚠️  無法辨識，請手動輸入')

        while True:
            if ai_price:
                prompt = f'  確認價格 NT$ {ai_price:,}（Enter 採用，或輸入新數字/s/q）: '
            else:
                prompt = f'[{i}/{len(files)}] {fname} 價格 NT$: '

            val = input(prompt).strip()

            if val.lower() == 'q':
                print('中止。')
                return []
            if val.lower() == 's':
                print(f'  跳過 {fname}')
                break
            # 直接按 Enter → 採用 AI 辨識結果
            if val == '' and ai_price:
                orders.append({'fname': fname, 'price': ai_price})
                print(f'  ✅ NT$ {ai_price:,}')
                break
            # 手動輸入（支援小數點格式）
            if val:
                parsed = parse_price_value(val)
                if parsed and parsed > 0:
                    orders.append({'fname': fname, 'price': parsed})
                    break
                print('  請輸入正整數或小數（如 1.2=12000），或輸入 s 跳過、q 中止')
            else:
                print('  請輸入價格，或輸入 s 跳過、q 中止')

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
