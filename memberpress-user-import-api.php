<?php
/**
 * Plugin Name: MemberPress User Import API
 * Description: Plugin para criar usuários no WordPress através de uma API REST com dados enviados em JSON.
 * Version: 1.0.0
 * Author: Tiago Lima
 * Author URI: https://taltecnologia.com.br
 */

/***
 * 
 *
 {
    "username": "api",
    "password": "9T5JZ9VyDAXE!yDWdg5rH7Zv"
}
 */

// Evitar acesso direto ao arquivo
if (!defined('ABSPATH')) {
    exit;
}

// Registrar a rota da API para importar usuários
add_action('rest_api_init', function () {
    register_rest_route('memberpress/v1', '/import-users', array(
        'methods'  => 'POST',
        'callback' => 'import_users_callback',
        'permission_callback' => function () {
            return current_user_can('manage_options'); // Permissão para administradores
        }
    ));

    // Registrar a rota para testar autenticação
    register_rest_route('memberpress/v1', '/test-auth', array(
        'methods'  => 'POST', // Alterar para POST
        'callback' => 'test_auth_callback',
        'permission_callback' => '__return_true' // Permissão livre, pois estamos testando autenticação
    ));
});

// Callback para importar usuários
function import_users_callback(WP_REST_Request $request) {
    $users = $request->get_param('users');

    if (empty($users)) {
        return new WP_Error('no_users', 'No users provided', array('status' => 400));
    }

    $imported_users = [];
    $failed_users = [];

    foreach ($users as $user) {
        $username = sanitize_user($user['username']);
        $email = sanitize_email($user['email']);
        $role = sanitize_text_field($user['role']);

        // Verifica se o usuário ou e-mail já existe
        if (username_exists($username) || email_exists($email)) {
            $failed_users[] = $username; // Adiciona usuário à lista de falhas
            continue;
        }

        // Cria o novo usuário
        $user_id = wp_create_user($username, wp_generate_password(), $email);

        if (!is_wp_error($user_id)) {
            $user = new WP_User($user_id);
            $user->set_role($role);
            $imported_users[] = $username; // Adiciona usuário à lista de importados
        } else {
            $failed_users[] = $username; // Se falhar, adicione à lista de falhas
        }
    }

    return rest_ensure_response(array(
        'success' => true,
        'imported' => $imported_users,
        'failed' => $failed_users,
        'message' => 'Importação concluída.'
    ));
}

// Callback para testar autenticação
function test_auth_callback(WP_REST_Request $request) {
    $username = $request->get_param('username'); // Obtém o usuário do corpo da requisição
    $password = $request->get_param('password'); // Obtém a senha do corpo da requisição

    // Verifica as credenciais
    $user = wp_authenticate($username, $password);

    if (is_wp_error($user)) {
        return new WP_Error('unauthorized', 'Invalid username or password', array('status' => 401));
    }

    return rest_ensure_response(array(
        'success' => true,
        'user' => array(
            'id' => $user->ID,
            'username' => $user->user_login,
            'email' => $user->user_email,
            'role' => $user->roles,
        )
    ));
}