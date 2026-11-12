ps.setString(1, x);
conn.prepareStatement("SELECT * FROM t WHERE a=?");
