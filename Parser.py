import sys
import sqlite3
import requests
from bs4 import BeautifulSoup

# отключил проверку сертификата и эта строчка нужна, 
# чтобы предупреждений об отключенной проверки не было
requests.packages.urllib3.disable_warnings()

if __name__ == "__main__":
    # получаем имя продукта
    product_name = ""
    if len(sys.argv) == 1:
        print("Не задано имя продукта")
        exit()
    else:
        for i in range(1, len(sys.argv)):
            product_name = product_name + sys.argv[i]
            if i != len(sys.argv) - 1:
                product_name = product_name + " "
   
    response = requests.post('https://threats.kaspersky.com/en/vulnerability/')
    if response.status_code != requests.codes.ok:
        print("Status code страницы {}".format(response.status_code))
        exit()

    soup = BeautifulSoup(response.text, 'lxml')
    vulns = soup.find_all(class_ = 'line_info line_info_vendor line_list2')
    
    # в этом range задается количество страниц для пагинации
    for i in range(2, 6):
        form_data = {
            'action': 'infinite_scroll',
            'page_no': str(i),
            'post_type': 'vulnerability',
            'template': 'row_vulnerability4archive',
            'q': 'undefined',
        }

        response = requests.post('https://threats.kaspersky.com/en/wp-admin/admin-ajax.php', \
            cookies = response.cookies, data = form_data, verify=False)
        if response.status_code != requests.codes.ok:
            print("Status code страницы {}".format(response.status_code))
 
        soup = BeautifulSoup(response.text, 'lxml')
        vulns = vulns + soup.find_all(class_ = 'line_info line_info_vendor line_list2')

    rows = []
    for i in  vulns:
        temp = []
        for j in i.find_all('td'):
            temp.append(j)
        rows.append(temp)

    write2bd = []
    for i in rows:
        if i[2].text.strip() == product_name:
            # переход на страницу описания уязвимости
            url = i[0].find('a').get('href')
            response_cve_id = requests.get(url)
            if response_cve_id.status_code != requests.codes.ok:
                print("Status code страницы c описанием уязвимости {}".format(response.status_code))
            
            # собираем cve
            soup_cve_id = BeautifulSoup(response_cve_id.text, 'lxml')
            cve_id = ""
            # эта проверка понадобилась, потому что на сайте
            # не для всех уязвимостей есть cve
            if soup_cve_id.find(class_ = 'cve-ids-list') != None:
                cve_id = cve_id + (soup_cve_id.find(class_ = 'cve-ids-list').text)

            # собираем ссыслки на cve
            cve_links = ""
            temp = soup_cve_id.find_all(class_ = 'gtm_vulnerabilities_cve', href = True)
            for  j in  temp:
                cve_links = cve_links + j['href']
            
            write2bd.append([product_name, i[0].text.strip(), i[1].text.strip(), cve_id, cve_links])

    # если ранее не была создана БД, она создастся
    # иначе подключимся к уже существующей
    conn = sqlite3.connect("kaspersky_test_task_bd.db")
    cursor = conn.cursor()

    # если таблица уязвимостей не была ранее создана, она создастся
    # иначе будем работать с уже существующей
    cursor.execute("""CREATE TABLE IF NOT EXISTS vulnerabilities
                  (product_name text, kaspersky_lab_id text, name text, cve text, cve_links text)""")

    # запись в БД
    # есть проверка, которая позволяет при повторном запуске скрипта не дублировать записи в БД
    for i in write2bd:
        notdublicate = True
        for row in cursor.execute("SELECT cve FROM vulnerabilities"):
            if str(row)[2:16] == i[3][:14]:
                notdublicate = False
                break
        if notdublicate:
            cursor.execute("INSERT INTO vulnerabilities VALUES ('" + i[0] + "', '" +\
                 i[1] + "', '" + i[2] + "', '" + i[3] + "', '" + i[4] + "')")

    conn.commit()

    # печать содержимого БД
    for row in cursor.execute("SELECT * FROM vulnerabilities ORDER BY product_name"):
        print(row)
