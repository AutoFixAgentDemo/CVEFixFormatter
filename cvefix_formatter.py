import sqlite3


def fetch_cve_data(db_path):
    # 连接到数据库
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # 编写 SQL 查询语句
    # 注意：根据实际表名和字段名进行对应修改
    query = """
    SELECT
        cve.cve_id                        AS CVE编号,
        cwe.cwe_id                        AS CWE编号,
        cve.description                   AS CVE描述,
        fixes.hash                        AS 补丁sha,
        repository.repo_name             AS repo_name,
        commits.msg                      AS commit_message,
        file_change.code_before          AS code_before,
        file_change.code_after           AS code_after,
        file_change.diff                 AS diff
    FROM cve
    -- 连接 cwe_classification 获取 CVE<->CWE 的映射
    LEFT JOIN cwe_classification
           ON cve.cve_id = cwe_classification.cve_id
    -- 再连接 cwe 表，以获取 CWE 详细信息
    LEFT JOIN cwe
           ON cwe_classification.cwe_id = cwe.cwe_id
    -- 连接 fixes 表，查看哪些 commit 修复了该 CVE
    LEFT JOIN fixes
           ON cve.cve_id = fixes.cve_id
    -- 连接 commits 表，获取对应补丁的提交信息
    LEFT JOIN commits
           ON fixes.hash = commits.hash
          AND fixes.repo_url = commits.repo_url
    -- 连接 repository 表，获取仓库信息
    LEFT JOIN repository
           ON commits.repo_url = repository.repo_url
    -- 连接 file_change 表，提取修改前后代码与 diff
    LEFT JOIN file_change
           ON commits.hash = file_change.hash
    LIMIT 1
    """

    cursor.execute(query)
    rows = cursor.fetchall()

    # 可选：获取列名
    col_names = [desc[0] for desc in cursor.description]

    # 关闭连接
    cursor.close()
    conn.close()

    # 返回数据和列名（如有需要）
    return col_names, rows


if __name__ == "__main__":
    db_path = "/home/louisliu/Data/cvefix_data/CVEfixes_v1.0.8/Data/CVEfixes.db"  # 替换为自己的数据库文件
    columns, data = fetch_cve_data(db_path)

    # 输出结果示例
    print(" | ".join(columns))
    for row in data:
        print(" | ".join(str(item) if item is not None else "" for item in row))
