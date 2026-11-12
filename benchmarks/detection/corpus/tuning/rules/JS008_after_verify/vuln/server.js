const u = jwt.decode(t);
if (u.admin) grant();
