def health(status):
    return {"ok": status == "ready", "status": status}
