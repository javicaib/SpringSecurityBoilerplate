-- Insertar permisos
INSERT INTO permissions (name) VALUES ('READ');
INSERT INTO permissions (name) VALUES ('WRITE');
INSERT INTO permissions (name) VALUES ('DELETE');
INSERT INTO permissions (name) VALUES ('UPDATE');

-- Insertar roles
INSERT INTO roles (role_name) VALUES ('ADMIN');
INSERT INTO roles (role_name) VALUES ('USER');
INSERT INTO roles (role_name) VALUES ('MANAGER');
INSERT INTO roles (role_name) VALUES ('MODERATOR');
INSERT INTO roles (role_name) VALUES ('GUEST');

-- Asignar permisos al rol ADMIN
INSERT INTO role_permissions (role_id, permission_id) VALUES (1, 1); -- READ
INSERT INTO role_permissions (role_id, permission_id) VALUES (1, 2); -- WRITE
INSERT INTO role_permissions (role_id, permission_id) VALUES (1, 3); -- DELETE
INSERT INTO role_permissions (role_id, permission_id) VALUES (1, 4); -- UPDATE

-- Asignar permisos al rol USER
INSERT INTO role_permissions (role_id, permission_id) VALUES (2, 1); -- READ

-- Asignar permisos al rol MANAGER
INSERT INTO role_permissions (role_id, permission_id) VALUES (3, 1); -- READ
INSERT INTO role_permissions (role_id, permission_id) VALUES (3, 2); -- WRITE
INSERT INTO role_permissions (role_id, permission_id) VALUES (3, 4); -- UPDATE

-- Asignar permisos al rol MODERATOR
INSERT INTO role_permissions (role_id, permission_id) VALUES (4, 1); -- READ
INSERT INTO role_permissions (role_id, permission_id) VALUES (4, 3); -- DELETE

-- Asignar permisos al rol GUEST
INSERT INTO role_permissions (role_id, permission_id) VALUES (5, 1); -- READ

-- Insertar usuarios
INSERT INTO users (username, password, is_enabled, account_No_Expired, account_No_Locked, credential_No_Expired)
VALUES ('admin', 'adminPasswordHash', true, true, true, true);

INSERT INTO users (username, password, is_enabled, account_No_Expired, account_No_Locked, credential_No_Expired)
VALUES ('user', 'userPasswordHash', true, true, true, true);

INSERT INTO users (username, password, is_enabled, account_No_Expired, account_No_Locked, credential_No_Expired)
VALUES ('manager', 'managerPasswordHash', true, true, true, true);

INSERT INTO users (username, password, is_enabled, account_No_Expired, account_No_Locked, credential_No_Expired)
VALUES ('moderator', 'moderatorPasswordHash', true, true, true, true);

INSERT INTO users (username, password, is_enabled, account_No_Expired, account_No_Locked, credential_No_Expired)
VALUES ('guest', 'guestPasswordHash', true, true, true, true);

-- Asignar roles a los usuarios
INSERT INTO user_roles (user_id, role_id) VALUES (1, 1); -- admin - ADMIN
INSERT INTO user_roles (user_id, role_id) VALUES (2, 2); -- user - USER
INSERT INTO user_roles (user_id, role_id) VALUES (3, 3); -- manager - MANAGER
INSERT INTO user_roles (user_id, role_id) VALUES (4, 4); -- moderator - MODERATOR
INSERT INTO user_roles (user_id, role_id) VALUES (5, 5); -- guest - GUEST
