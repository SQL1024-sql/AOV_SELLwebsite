import os
import re
from PIL import Image
import openpyxl

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
IMG_DIR    = os.path.join(SCRIPT_DIR, 'acc_img')
XLSX_PATH  = os.path.join(SCRIPT_DIR, '圖片清單.xlsx')
IMG_EXTS   = {'.jpg', '.jpeg', '.png', '.gif', '.webp'}

# ══════════════════════════════════════════════════════
# OCR 辨識價格（PaddleOCR PP-OCRv4）
# ══════════════════════════════════════════════════════
try:
    from paddleocr import PaddleOCR
    _ocr = PaddleOCR(use_angle_cls=True, lang='ch')
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
    decimal_pat = re.compile(r'\b(\d{1,2}\.\d)\b')
    integer_pat = re.compile(r'\b(\d{3,6})\b')

    for text in candidates:
        m = decimal_pat.search(text)
        if m:
            return parse_price_value(m.group(1))

    for text in candidates:
        m = integer_pat.search(text)
        if m:
            return parse_price_value(m.group(1))

    return None


def recognize_price_with_ocr(img_path: str) -> int | None:
    if not OCR_AVAILABLE:
        return None
    try:
        result = _ocr.ocr(img_path, cls=True)
        if not result or not result[0]:
            return None
        texts = [line[1][0] for line in result[0] if line[1][1] > 0.5]
        return _pick_best_price(texts)
    except Exception as e:
        print(f'  ⚠️  OCR 辨識失敗：{e}')
        return None


def recognize_price(img_path: str) -> tuple[int | None, str]:
    if OCR_AVAILABLE:
        price = recognize_price_with_ocr(img_path)
        if price:
            return price, 'OCR'
    return None, ''


# ══════════════════════════════════════════════════════
# 步驟 1：辨識 acc_img/ 裡的圖片並收集價格
# ══════════════════════════════════════════════════════
def collect_prices():
    files = sorted([
        f for f in os.listdir(IMG_DIR)
        if os.path.splitext(f)[1].lower() in IMG_EXTS
    ])

    if not files:
        print('❌ acc_img/ 資料夾裡沒有圖片，請先把圖片放進去。')
        return []

    if OCR_AVAILABLE:
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
        stem = os.path.splitext(fname)[0]

        try:
            img = Image.open(img_path)
            img.show()
        except Exception as e:
            print(f'  無法開啟圖片：{e}')

        ai_price = None
        if OCR_AVAILABLE:
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
            if val == '' and ai_price:
                orders.append({'stem': stem, 'price': ai_price})
                print(f'  ✅ NT$ {ai_price:,}')
                break
            if val:
                parsed = parse_price_value(val)
                if parsed and parsed > 0:
                    orders.append({'stem': stem, 'price': parsed})
                    break
                print('  請輸入正整數或小數（如 1.2=12000），或輸入 s 跳過、q 中止')
            else:
                print('  請輸入價格，或輸入 s 跳過、q 中止')

    return orders


# ══════════════════════════════════════════════════════
# 步驟 2：清空並寫入 圖片清單.xlsx
# ══════════════════════════════════════════════════════
def write_xlsx(orders):
    print('\n── 確認清單 ──────────────────────────')
    for o in orders:
        print(f'  {o["stem"]:30s}  NT$ {o["price"]:,}')
    print(f'──────────────────────────────────────')
    print(f'共 {len(orders)} 筆，準備寫入 圖片清單.xlsx。')

    confirm = input('\n確認寫入？(y/n): ').strip().lower()
    if confirm != 'y':
        print('取消。')
        return

    # 清空並重建工作表
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = 'Sheet1'

    for o in orders:
        ws.append([o['stem'], None, o['price']])

    wb.save(XLSX_PATH)
    print(f'\n🎉 已寫入 {len(orders)} 筆資料到 圖片清單.xlsx')


# ══════════════════════════════════════════════════════
if __name__ == '__main__':
    print('=== AOV 圖片清單產生工具 ===\n')
    orders = collect_prices()
    if orders:
        write_xlsx(orders)
