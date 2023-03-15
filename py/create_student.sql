CREATE TABLE student (
                         id INT(11) NOT NULL AUTO_INCREMENT,
                         name VARCHAR(50) NOT NULL,
                         age INT(11) NOT NULL,
                         sex VARCHAR(10) NOT NULL,
                         grade VARCHAR(10) NOT NULL,
                         phone VARCHAR(30) NOT NULL,
                         address VARCHAR(200) NOT NULL,
                         idcard VARCHAR(50) NOT NULL,
                         PRIMARY KEY (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
