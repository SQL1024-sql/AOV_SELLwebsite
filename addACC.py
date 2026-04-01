import pandas as pd
import json
import os

def generate_json_from_excel(excel_path, folder_path, output_json):
    # 1. 讀取 Excel 檔案
    # header=None 表示 Excel 第一列就是資料（沒有標題列）
    # usecols="A,C" 表示只讀取 A 欄 (ID) 和 C 欄 (Price)
    try:
        df = pd.read_excel(excel_path, header=None, usecols=[0, 2], names=['file_id', 'price'], engine='openpyxl')
    except Exception as e:
        print(f"讀取 Excel 失敗: {e}")
        return

    # 處理 ID：轉為字串並補足 8 位數 (例如 1 -> 00000001)，方便匹配檔名
    df['file_id'] = df['file_id'].astype(str).str.zfill(8)
    
    # 建立價格查找地圖
    price_map = dict(zip(df['file_id'], df['price']))
    
    result_json = []
    auto_increment_id = 1  # JSON 裡的 id，從 1 開始依序累加
    
    # 2. 獲取資料夾內所有圖片（支援 png, jpg, jpeg）
    valid_extensions = ('.png', '.jpg', '.jpeg')
    if not os.path.exists(folder_path):
        print(f"錯誤：找不到資料夾 {folder_path}")
        return

    # 取得檔案清單並排序，確保 id 增加的順序一致
    files = sorted([f for f in os.listdir(folder_path) if f.lower().endswith(valid_extensions)])
    
    # 3. 比對資料並建立 JSON 物件
    for filename in files:
        # 取得主檔名 (例如 "00000001")
        name_only = os.path.splitext(filename)[0]
        
        if name_only in price_map:
            item = {
                "id": auto_increment_id,
                "price": int(price_map[name_only]),
                "imgNAME": filename
            }
            result_json.append(item)
            auto_increment_id += 1
        else:
            print(f"跳過：圖片 {filename} 不在 Excel 的名單中")

    # 4. 寫入 JSON 檔
    with open(output_json, 'w', encoding='utf-8') as f:
        json.dump(result_json, f, indent=2, ensure_ascii=False)
    
    print(f"完成！已產生 {len(result_json)} 筆資料到 {output_json}")

# --- 修改成你的實際路徑 ---
EXCEL_FILE = '圖片清單.xlsx'   # 你的 Excel 檔名
IMAGE_FOLDER = './pic'     # 你的圖片資料夾
OUTPUT_JSON = 'result.json'   # 要輸出的 JSON 檔名

generate_json_from_excel(EXCEL_FILE, IMAGE_FOLDER, OUTPUT_JSON)
