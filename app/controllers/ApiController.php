<?php
defined('PREVENT_DIRECT_ACCESS') OR exit('No direct script access allowed');

/**
 * Controller: ApiController
 * 
 * Automatically generated via CLI.
 */
class ApiController extends Controller {
    private $user_id;

    public function __construct()
    {
        parent::__construct();
        $this->call->database();
        $this->call->library('api');
    }
    
    public function login()
    {
        $this->api->require_method('POST');
        $this->api->rate_limit('login', 5, 60); // 5 requests per minute

        $input = $this->api->body();

        $username = trim($input['username'] ?? '');
        $password = $input['password'] ?? '';

        if (empty($username) || empty($password)) {
            $this->api->respond_error('Username and password are required.', 400);
        }
        $user = $this->db->raw(
            "SELECT id, username, password, role FROM users WHERE username = ? LIMIT 1",
            [$username]
        )->fetch(PDO::FETCH_ASSOC);

        if (!$user || !password_verify($password, $user['password'])) {
            $this->api->respond_error('Invalid username or password.', 401);
        }

        $tokens = $this->api->issue_tokens([
            'id' => $user['id'],
            'role' => $user['role']
        ]);

        $this->api->respond([
            'message' => 'Login successful.',
            'tokens' => $tokens
        ]);
    }

    public function refresh()
    {
        $this->api->require_method('POST');
        $this->api->rate_limit('refresh', 20, 60);

        $input = $this->api->body();
        $refresh_token = trim($input['refresh_token'] ?? '');

        if (empty($refresh_token)) {
            $this->api->respond_error('Refresh token is required.', 422);
        }
        $this->api->refresh_access_token($refresh_token);
    }

    public function logout()
    {
        $this->api->require_method('POST');

        $input = $this->api->body();
        $refresh_token = trim($input['refresh_token'] ?? '');

        if (empty($refresh_token)) {
            $this->api->respond_error('Refresh token is required.', 422);
        }

        $this->api->revoke_refresh_token($refresh_token);
        $this->api->respond(['message' => 'Logged out successfully.']);
    }

    public function create()
    {
        $this->api->require_method('POST');
        $this->api->rate_limit('register', 5, 300); // 10 requests per minute

        $input = $this->api->body();

        $username = is_string($input['username'] ?? null) ? trim($input['username']) : '';
        $email = is_string($input['email'] ?? null) ? trim($input['email']) : '';
        $password = $input['password'] ?? '';
        $role = 'user';

        if (array_key_exists('role', $input)) {
            if (!is_string($input['role'])) {
                $this->api->respond_error('Role must be a string.', 422);
            }

            $requested_role = strtolower(trim($input['role']));
            if (!in_array($requested_role, ['user', 'admin'], true)) {
                $this->api->respond_error('Invalid role.', 422);
            }

            $role = $requested_role;
        }

        // Validation
        if (empty($username) || empty($email) || empty($password)) {
            $this->api->respond_error('Username, email, and password are required.', 400);
        }

        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $this->api->respond_error('Invalid email format.', 422);
        }

        if(strlen($password) < 8) {
            $this->api->respond_error('Password must be at least 8 characters long.', 422);
        }

        // Check if user exist
        $existing = $this->db->raw(
            "SELECT id FROM users WHERE username = ? OR email = ? LIMIT 1",
            [$username, $email]
        )->fetch(PDO::FETCH_ASSOC);

        if ($existing) {
            $this->api->respond_error('Username or email already exists.', 422);
        }

        $hashed_password = password_hash($password, PASSWORD_DEFAULT);

        $this->db->raw(
            "INSERT INTO users (username, email, password, role, created_at)
            VALUES (?, ?, ?, ?, NOW())",
            [$username, $email, $hashed_password, $role]
        );

        $new_id = $this->db->last_id();

        $this->api->respond([
            'message' => 'User created successfully.',
            'user_id' => $new_id
        ], 201);
    }

    public function list()
    {
        $this->api->require_method('GET');
        $auth = $this->api->require_jwt();

        if ($auth['role'] !== 'admin') {
            $this->api->respond_error('Unauthorized access.', 403);
        }

        $users = $this->db->raw(
            'SELECT id, username, email, role, created_at FROM users ORDER BY id'
        )->fetchAll(PDO::FETCH_ASSOC);

        $this->api->respond(['data' => $users]);
    }

    public function profile()
    {
        $this->api->require_method('GET');
        $auth = $this->api->require_jwt();

        $this->user_id = $auth['sub'];
        $user = $this->db->raw(
            "SELECT id, username, email, role, created_at FROM users WHERE id = ? LIMIT 1",
            [$this->user_id]
        )->fetch(PDO::FETCH_ASSOC);

        if (!$user) {
            $this->api->respond_error('User not found.', 404);
        }

        $this->api->respond($user);
    }

    public function update($id)
    {
        $this->api->require_method('PUT');
        $auth = $this->api->require_jwt();
        $id = filter_var($id, FILTER_VALIDATE_INT, ['options' => ['min_range' => 1]]);

        if ($id === false) {
            $this->api->respond_error('Invalid user ID.', 422);
        }

        $user = $this->db->raw(
            'SELECT id, username, email, role, created_at FROM users WHERE id = ? LIMIT 1',
            [$id]
        )->fetch(PDO::FETCH_ASSOC);

        if (!$user) {
            $this->api->respond_error('User not found.', 404);
        }

        $is_admin = ($auth['role'] ?? '') === 'admin';
        if (!$is_admin && (string) $auth['sub'] !== (string) $user['id']) {
            $this->api->respond_error('Unauthorized access.', 403);
        }

        $input = $this->api->body();
        $updates = [];
        $values = [];

        if (array_key_exists('username', $input)) {
            if (!is_string($input['username'])) {
                $this->api->respond_error('Username must be a string.', 422);
            }
            $username = trim($input['username']);
            if ($username === '') {
                $this->api->respond_error('Username cannot be empty.', 422);
            }
            $updates[] = 'username = ?';
            $values[] = $username;
            $user['username'] = $username;
        }

        if (array_key_exists('email', $input)) {
            if (!is_string($input['email'])) {
                $this->api->respond_error('Email must be a string.', 422);
            }
            $email = trim($input['email']);
            if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
                $this->api->respond_error('Invalid email format.', 422);
            }
            $updates[] = 'email = ?';
            $values[] = $email;
            $user['email'] = $email;
        }

        if (array_key_exists('role', $input)) {
            if (!$is_admin) {
                $this->api->respond_error('Only administrators can change user roles.', 403);
            }
            if (!is_string($input['role'])) {
                $this->api->respond_error('Role must be a string.', 422);
            }
            $role = strtolower(trim($input['role']));
            if (!in_array($role, ['user', 'admin', 'editor'], true)) {
                $this->api->respond_error('Invalid role.', 422);
            }
            $updates[] = 'role = ?';
            $values[] = $role;
            $user['role'] = $role;
        }

        if (!$updates) {
            $this->api->respond_error('Provide a username, email, or role to update.', 422);
        }

        $duplicate = $this->db->raw(
            'SELECT id FROM users WHERE (username = ? OR email = ?) AND id <> ? LIMIT 1',
            [$user['username'], $user['email'], $id]
        )->fetch(PDO::FETCH_ASSOC);

        if ($duplicate) {
            $this->api->respond_error('Username or email already exists.', 422);
        }

        $values[] = $id;
        $this->db->raw(
            'UPDATE users SET ' . implode(', ', $updates) . ', updated_at = NOW() WHERE id = ?',
            $values
        );

        $user['id'] = $id;
        $this->api->respond([
            'message' => 'User updated successfully.',
            'user' => $user
        ]);
    }

    public function delete($id)
    {
        $this->api->require_method('DELETE');
        $auth = $this->api->require_jwt();
        $id = filter_var($id, FILTER_VALIDATE_INT, ['options' => ['min_range' => 1]]);

        if ($id === false) {
            $this->api->respond_error('Invalid user ID.', 422);
        }

        $user = $this->db->raw(
            'SELECT id FROM users WHERE id = ? LIMIT 1',
            [$id]
        )->fetch(PDO::FETCH_ASSOC);

        if (!$user) {
            $this->api->respond_error('User not found.', 404);
        }

        $is_admin = ($auth['role'] ?? '') === 'admin';
        if (!$is_admin && (string) $auth['sub'] !== (string) $user['id']) {
            $this->api->respond_error('Unauthorized access.', 403);
        }

        $this->db->raw('DELETE FROM refresh_tokens WHERE user_id = ?', [$id]);
        $this->db->raw('DELETE FROM users WHERE id = ?', [$id]);

        $this->api->respond(['message' => 'User deleted successfully.']);
    }

    public function products()
    {
        $this->api->require_method('GET');
        $this->api->require_jwt();

        $products = $this->db->raw(
            'SELECT id, product_name, description, price, quantity, created_at FROM products ORDER BY id DESC'
        )->fetchAll(PDO::FETCH_ASSOC);

        $this->api->respond(['data' => $products]);
    }

    public function product($id)
    {
        $this->api->require_method('GET');
        $this->api->require_jwt();
        $id = $this->validated_product_id($id);

        $product = $this->db->raw(
            'SELECT id, product_name, description, price, quantity, created_at FROM products WHERE id = ? LIMIT 1',
            [$id]
        )->fetch(PDO::FETCH_ASSOC);

        if (!$product) {
            $this->api->respond_error('Product not found.', 404);
        }

        $this->api->respond($product);
    }

    public function create_product()
    {
        $this->api->require_method('POST');
        $this->require_admin_product_write();

        $fields = $this->validated_product_fields($this->api->body());
        $this->db->raw(
            'INSERT INTO products (product_name, description, price, quantity) VALUES (?, ?, ?, ?)',
            [$fields['product_name'], $fields['description'], $fields['price'], $fields['quantity']]
        );

        $product = $this->db->raw(
            'SELECT id, product_name, description, price, quantity, created_at FROM products WHERE id = ? LIMIT 1',
            [$this->db->last_id()]
        )->fetch(PDO::FETCH_ASSOC);

        $this->api->respond([
            'message' => 'Product created successfully.',
            'data' => $product
        ], 201);
    }

    public function update_product($id)
    {
        $method = strtoupper($_SERVER['REQUEST_METHOD'] ?? '');
        if (!in_array($method, ['PUT', 'PATCH'], true)) {
            $this->api->respond_error('Method Not Allowed', 405);
        }
        $this->require_admin_product_write();
        $id = $this->validated_product_id($id);

        $exists = $this->db->raw(
            'SELECT id FROM products WHERE id = ? LIMIT 1',
            [$id]
        )->fetch(PDO::FETCH_ASSOC);
        if (!$exists) {
            $this->api->respond_error('Product not found.', 404);
        }

        $input = $this->api->body();
        if ($method === 'PUT') {
            foreach (['product_name', 'description', 'price', 'quantity'] as $field) {
                if (!array_key_exists($field, $input)) {
                    $this->api->respond_error('PUT requires product_name, description, price, and quantity.', 422);
                }
            }
        }
        $fields = $this->validated_product_fields($input, $method === 'PATCH');

        $assignments = [];
        $values = [];
        foreach ($fields as $field => $value) {
            $assignments[] = $field . ' = ?';
            $values[] = $value;
        }
        $values[] = $id;
        $this->db->raw(
            'UPDATE products SET ' . implode(', ', $assignments) . ' WHERE id = ?',
            $values
        );

        $product = $this->db->raw(
            'SELECT id, product_name, description, price, quantity, created_at FROM products WHERE id = ? LIMIT 1',
            [$id]
        )->fetch(PDO::FETCH_ASSOC);

        $this->api->respond([
            'message' => 'Product updated successfully.',
            'data' => $product
        ]);
    }

    public function delete_product($id)
    {
        $this->api->require_method('DELETE');
        $this->require_admin_product_write();
        $id = $this->validated_product_id($id);

        $deleted = $this->db->raw('DELETE FROM products WHERE id = ?', [$id]);
        if ($deleted->rowCount() === 0) {
            $this->api->respond_error('Product not found.', 404);
        }

        $this->api->respond(['message' => 'Product deleted successfully.']);
    }

    private function require_admin_product_write()
    {
        $auth = $this->api->require_jwt();
        if (($auth['role'] ?? '') !== 'admin') {
            $this->api->respond_error('Only administrators can modify products.', 403);
        }
    }

    private function validated_product_id($id)
    {
        $id = filter_var($id, FILTER_VALIDATE_INT, ['options' => ['min_range' => 1]]);
        if ($id === false) {
            $this->api->respond_error('Invalid product ID.', 422);
        }

        return $id;
    }

    private function validated_product_fields($input, $partial = false)
    {
        if (!is_array($input)) {
            $this->api->respond_error('A JSON object is required.', 422);
        }

        $allowed = ['product_name', 'description', 'price', 'quantity'];
        foreach (array_keys($input) as $field) {
            if (!in_array($field, $allowed, true)) {
                $this->api->respond_error('Unknown product field.', 422);
            }
        }

        if ($partial && !$input) {
            $this->api->respond_error('Provide at least one product field to update.', 422);
        }
        if (!$partial) {
            foreach (['product_name', 'price', 'quantity'] as $field) {
                if (!array_key_exists($field, $input)) {
                    $this->api->respond_error('Product name, price, and quantity are required.', 422);
                }
            }
        }

        $fields = [];
        if (array_key_exists('product_name', $input)) {
            if (!is_string($input['product_name'])) {
                $this->api->respond_error('Product name must be a string.', 422);
            }
            $name = trim(htmlspecialchars_decode($input['product_name'], ENT_QUOTES));
            if ($name === '' || preg_match('/^.{1,100}$/us', $name) !== 1) {
                $this->api->respond_error('Product name must contain between 1 and 100 characters.', 422);
            }
            $fields['product_name'] = $name;
        }

        if (array_key_exists('description', $input)) {
            if (!is_string($input['description'])) {
                $this->api->respond_error('Description must be a string.', 422);
            }
            $description = htmlspecialchars_decode($input['description'], ENT_QUOTES);
            if (strlen($description) > 65535) {
                $this->api->respond_error('Description is too long.', 422);
            }
            $fields['description'] = $description;
        } elseif (!$partial) {
            $fields['description'] = '';
        }

        if (array_key_exists('price', $input)) {
            if (!is_string($input['price']) && !is_int($input['price']) && !is_float($input['price'])) {
                $this->api->respond_error('Price must be a non-negative amount with up to 2 decimal places.', 422);
            }
            $price = (string) $input['price'];
            if (!preg_match('/^(?:0|[1-9][0-9]{0,7})(?:\.[0-9]{1,2})?$/D', $price)) {
                $this->api->respond_error('Price must be between 0 and 99999999.99 with up to 2 decimal places.', 422);
            }
            $parts = explode('.', $price, 2);
            $fields['price'] = $parts[0] . '.' . str_pad($parts[1] ?? '', 2, '0');
        }

        if (array_key_exists('quantity', $input)) {
            if (!is_string($input['quantity']) && !is_int($input['quantity'])) {
                $this->api->respond_error('Quantity must be a non-negative integer.', 422);
            }
            $quantity = filter_var($input['quantity'], FILTER_VALIDATE_INT, [
                'options' => ['min_range' => 0, 'max_range' => 2147483647]
            ]);
            if ($quantity === false) {
                $this->api->respond_error('Quantity must be a non-negative integer.', 422);
            }
            $fields['quantity'] = $quantity;
        }

        return $fields;
    }

}
