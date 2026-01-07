# utils/filters.py

def build_filters(request):
    filters = []
    params = []

    start = request.args.get("start")
    if start:
        filters.append("timestamp >= ?")
        params.append(start.replace("T", " ") + ":00")

    end = request.args.get("end")
    if end:
        filters.append("timestamp <= ?")
        params.append(end.replace("T", " ") + ":59")

    ip = request.args.get("ip")
    if ip:
        filters.append("ip LIKE ?")
        params.append(f"%{ip}%")

    method = request.args.get("method")
    if method:
        filters.append("method = ?")
        params.append(method)

    status = request.args.get("status")
    if status:
        filters.append("status = ?")
        params.append(status)

    where_clause = "WHERE " + " AND ".join(filters) if filters else ""
    return where_clause, params
