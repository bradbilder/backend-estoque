/**
 * ====================================================================================
 * STOCKFLOW - BACKEND API
 * Sistema de Controle de Estoque Web - v2.1
 * ====================================================================================
 */

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');

const app = express();

// ====================================================================================
// MIDDLEWARE
// ====================================================================================

app.use(cors({
    origin: '*',
    credentials: true
}));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// ====================================================================================
// CONFIGURAÇÃO DO BANCO DE DADOS
// ====================================================================================

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// ====================================================================================
// FUNÇÃO AUXILIAR PARA ADICIONAR COLUNA SE NÃO EXISTIR
// ====================================================================================

async function addColumnIfNotExists(table, column, type) {
    try {
        // Verifica se a coluna já existe
        const checkQuery = `
            SELECT column_name 
            FROM information_schema.columns 
            WHERE table_name = $1 AND column_name = $2
        `;
        const result = await pool.query(checkQuery, [table, column]);
        
        if (result.rows.length === 0) {
            // Coluna não existe, adicionar
            await pool.query(`ALTER TABLE ${table} ADD COLUMN ${column} ${type}`);
            console.log(`✅ Coluna ${column} adicionada na tabela ${table}`);
        } else {
            console.log(`ℹ️ Coluna ${column} já existe na tabela ${table}`);
        }
    } catch (error) {
        console.error(`❌ Erro ao adicionar coluna ${column}:`, error.message);
    }
}

// ====================================================================================
// FUNÇÕES DE BANCO DE DADOS
// ====================================================================================

async function initializeDatabase() {
    try {
        // Tabela de usuários
        await pool.query(`
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                email VARCHAR(255) UNIQUE NOT NULL,
                password VARCHAR(255) NOT NULL,
                role VARCHAR(50) DEFAULT 'funcionario',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);
        console.log('✅ Tabela users OK');

        // Tabela de produtos (estrutura básica)
        await pool.query(`
            CREATE TABLE IF NOT EXISTS products (
                id SERIAL PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                barcode VARCHAR(255) UNIQUE,
                quantity INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);
        console.log('✅ Tabela products OK');

        // Tabela de histórico (estrutura básica)
        await pool.query(`
            CREATE TABLE IF NOT EXISTS history (
                id SERIAL PRIMARY KEY,
                product_id INTEGER,
                action VARCHAR(50) NOT NULL,
                quantity INTEGER DEFAULT 0,
                user_id INTEGER,
                date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                product_name VARCHAR(255)
            )
        `);
        console.log('✅ Tabela history OK');

        // ✅ ADICIONAR COLUNAS NOVAS NA TABELA PRODUCTS
        console.log('🔧 Verificando colunas da tabela products...');
        await addColumnIfNotExists('products', 'category', "VARCHAR(100) DEFAULT 'Higiene'");
        await addColumnIfNotExists('products', 'unit', "VARCHAR(20) DEFAULT 'un'");
        await addColumnIfNotExists('products', 'price', 'DECIMAL(10,2) DEFAULT 0');
        await addColumnIfNotExists('products', 'min_quantity', 'INTEGER DEFAULT 5');
        await addColumnIfNotExists('products', 'description', 'TEXT');

        // ✅ ADICIONAR COLUNA NOVA NA TABELA HISTORY
        console.log('🔧 Verificando colunas da tabela history...');
        await addColumnIfNotExists('history', 'total_value', 'DECIMAL(10,2) DEFAULT 0');

        // Criar usuário admin padrão se não existir
        const adminEmail = process.env.ADMIN_EMAIL || 'admin@stockflow.com';
        const adminPassword = process.env.ADMIN_PASSWORD || 'admin123';
        
        const adminExists = await pool.query('SELECT * FROM users WHERE email = $1', [adminEmail]);
        
        if (adminExists.rows.length === 0) {
            const hashedPassword = await bcrypt.hash(adminPassword, 12);
            await pool.query(
                'INSERT INTO users (name, email, password, role) VALUES ($1, $2, $3, $4)',
                ['Administrador', adminEmail, hashedPassword, 'admin']
            );
            console.log('✅ Usuário admin criado:', adminEmail);
        }

        console.log('✅ Banco de dados inicializado com sucesso!');
        
    } catch (error) {
        console.error('❌ Erro ao inicializar banco de dados:', error);
        process.exit(1);
    }
}

// ====================================================================================
// MIDDLEWARE DE AUTENTICAÇÃO
// ====================================================================================

function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Token não fornecido' });
    }

    jwt.verify(token, process.env.JWT_SECRET || 'sua-chave-secreta-super-segura', (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Token inválido ou expirado' });
        }
        req.user = user;
        next();
    });
}

function requireAdmin(req, res, next) {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Acesso negado. Requer perfil administrador.' });
    }
    next();
}

// ====================================================================================
// ROTAS DE AUTENTICAÇÃO
// ====================================================================================

app.post('/auth/register', async (req, res) => {
    try {
        const { name, email, password, role = 'funcionario' } = req.body;

        if (!name || !email || !password) {
            return res.status(400).json({ error: 'Nome, email e senha são obrigatórios' });
        }

        if (password.length < 6) {
            return res.status(400).json({ error: 'Senha deve ter pelo menos 6 caracteres' });
        }

        const userExists = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
        
        if (userExists.rows.length > 0) {
            return res.status(400).json({ error: 'Email já cadastrado' });
        }

        const hashedPassword = await bcrypt.hash(password, 12);

        const result = await pool.query(
            'INSERT INTO users (name, email, password, role) VALUES ($1, $2, $3, $4) RETURNING id, name, email, role, created_at',
            [name, email, hashedPassword, role]
        );

        const user = result.rows[0];

        const token = jwt.sign(
            { id: user.id, email: user.email, role: user.role },
            process.env.JWT_SECRET || 'sua-chave-secreta-super-segura',
            { expiresIn: '7d' }
        );

        res.status(201).json({
            message: 'Usuário criado com sucesso',
            token,
            user: { id: user.id, name: user.name, email: user.email, role: user.role }
        });

    } catch (error) {
        console.error('Erro no registro:', error);
        res.status(500).json({ error: 'Erro interno do servidor' });
    }
});

app.post('/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({ error: 'Email e senha são obrigatórios' });
        }

        const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
        
        if (result.rows.length === 0) {
            return res.status(401).json({ error: 'Credenciais inválidas' });
        }

        const user = result.rows[0];

        const isValidPassword = await bcrypt.compare(password, user.password);
        
        if (!isValidPassword) {
            return res.status(401).json({ error: 'Credenciais inválidas' });
        }

        const token = jwt.sign(
            { id: user.id, email: user.email, role: user.role },
            process.env.JWT_SECRET || 'sua-chave-secreta-super-segura',
            { expiresIn: '7d' }
        );

        res.json({
            message: 'Login realizado com sucesso',
            token,
            user: { id: user.id, name: user.name, email: user.email, role: user.role }
        });

    } catch (error) {
        console.error('Erro no login:', error);
        res.status(500).json({ error: 'Erro interno do servidor' });
    }
});

// ====================================================================================
// ROTAS DE PRODUTOS
// ====================================================================================

/**
 * GET /products - Listar todos os produtos
 */
app.get('/products', authenticateToken, async (req, res) => {
    try {
        const { search, barcode, category } = req.query;
        let query = 'SELECT * FROM products';
        let params = [];
        let conditions = [];

        if (search) {
            conditions.push(`LOWER(name) LIKE LOWER($${params.length + 1})`);
            params.push(`%${search}%`);
        }
        
        if (barcode) {
            conditions.push(`barcode = $${params.length + 1}`);
            params.push(barcode);
        }

        if (category && category !== 'Todos') {
            conditions.push(`category = $${params.length + 1}`);
            params.push(category);
        }

        if (conditions.length > 0) {
            query += ' WHERE ' + conditions.join(' AND ');
        }

        query += ' ORDER BY name ASC';

        const result = await pool.query(query, params);
        
        // Garantir que os valores numéricos estão corretos
        const products = result.rows.map(p => ({
            ...p,
            quantity: parseInt(p.quantity) || 0,
            price: parseFloat(p.price) || 0,
            min_quantity: parseInt(p.min_quantity) || 5
        }));
        
        res.json(products);

    } catch (error) {
        console.error('Erro ao listar produtos:', error);
        res.status(500).json({ error: 'Erro interno do servidor' });
    }
});

/**
 * GET /products/:id - Buscar produto por ID
 */
app.get('/products/:id', authenticateToken, async (req, res) => {
    try {
        const { id } = req.params;
        const result = await pool.query('SELECT * FROM products WHERE id = $1', [id]);
        
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Produto não encontrado' });
        }
        
        const p = result.rows[0];
        res.json({
            ...p,
            quantity: parseInt(p.quantity) || 0,
            price: parseFloat(p.price) || 0,
            min_quantity: parseInt(p.min_quantity) || 5
        });

    } catch (error) {
        console.error('Erro ao buscar produto:', error);
        res.status(500).json({ error: 'Erro interno do servidor' });
    }
});

/**
 * POST /products - Criar novo produto
 */
app.post('/products', authenticateToken, async (req, res) => {
    try {
        const { 
            name, 
            barcode, 
            category = 'Higiene', 
            quantity = 0, 
            unit = 'un', 
            price = 0, 
            min_quantity = 5, 
            description = '' 
        } = req.body;

        console.log('📦 Criando produto:', { name, barcode, category, quantity, unit, price, min_quantity });

        if (!name) {
            return res.status(400).json({ error: 'Nome do produto é obrigatório' });
        }

        // Verificar código de barras duplicado
        if (barcode) {
            const barcodeExists = await pool.query('SELECT * FROM products WHERE barcode = $1', [barcode]);
            if (barcodeExists.rows.length > 0) {
                return res.status(400).json({ error: 'Código de barras já cadastrado' });
            }
        }

        // Converter valores para garantir tipos corretos
        const qty = parseInt(quantity) || 0;
        const prc = parseFloat(price) || 0;
        const minQty = parseInt(min_quantity) || 5;

        const result = await pool.query(
            `INSERT INTO products (name, barcode, category, quantity, unit, price, min_quantity, description) 
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING *`,
            [name, barcode || null, category, qty, unit, prc, minQty, description || '']
        );

        const product = result.rows[0];
        console.log('✅ Produto criado:', product);

        // Registrar no histórico
        const totalValue = qty * prc;
        await pool.query(
            'INSERT INTO history (product_id, action, quantity, user_id, product_name, total_value) VALUES ($1, $2, $3, $4, $5, $6)',
            [product.id, 'cadastro', qty, req.user.id, name, totalValue]
        );

        res.status(201).json({
            ...product,
            quantity: parseInt(product.quantity) || 0,
            price: parseFloat(product.price) || 0,
            min_quantity: parseInt(product.min_quantity) || 5
        });

    } catch (error) {
        console.error('❌ Erro ao criar produto:', error);
        res.status(500).json({ error: 'Erro interno do servidor: ' + error.message });
    }
});

/**
 * PUT /products/:id - Atualizar produto
 */
app.put('/products/:id', authenticateToken, async (req, res) => {
    try {
        const { id } = req.params;
        const { 
            name, 
            barcode, 
            category = 'Higiene', 
            quantity = 0, 
            unit = 'un', 
            price = 0, 
            min_quantity = 5, 
            description = '' 
        } = req.body;

        console.log('📝 Atualizando produto:', id, { name, barcode, category, quantity, unit, price, min_quantity });

        if (!name) {
            return res.status(400).json({ error: 'Nome do produto é obrigatório' });
        }

        const productExists = await pool.query('SELECT * FROM products WHERE id = $1', [id]);
        if (productExists.rows.length === 0) {
            return res.status(404).json({ error: 'Produto não encontrado' });
        }

        // Verificar código de barras duplicado (excluindo o produto atual)
        if (barcode) {
            const barcodeExists = await pool.query(
                'SELECT * FROM products WHERE barcode = $1 AND id != $2',
                [barcode, id]
            );
            if (barcodeExists.rows.length > 0) {
                return res.status(400).json({ error: 'Código de barras já cadastrado' });
            }
        }

        // Converter valores
        const qty = parseInt(quantity) || 0;
        const prc = parseFloat(price) || 0;
        const minQty = parseInt(min_quantity) || 5;

        const result = await pool.query(
            `UPDATE products SET 
                name = $1, 
                barcode = $2, 
                category = $3, 
                quantity = $4, 
                unit = $5, 
                price = $6, 
                min_quantity = $7, 
                description = $8,
                updated_at = CURRENT_TIMESTAMP 
             WHERE id = $9 RETURNING *`,
            [name, barcode || null, category, qty, unit, prc, minQty, description || '', id]
        );

        const product = result.rows[0];
        console.log('✅ Produto atualizado:', product);

        // Registrar no histórico
        const totalValue = qty * prc;
        await pool.query(
            'INSERT INTO history (product_id, action, quantity, user_id, product_name, total_value) VALUES ($1, $2, $3, $4, $5, $6)',
            [product.id, 'edicao', qty, req.user.id, name, totalValue]
        );

        res.json({
            ...product,
            quantity: parseInt(product.quantity) || 0,
            price: parseFloat(product.price) || 0,
            min_quantity: parseInt(product.min_quantity) || 5
        });

    } catch (error) {
        console.error('❌ Erro ao atualizar produto:', error);
        res.status(500).json({ error: 'Erro interno do servidor: ' + error.message });
    }
});

/**
 * DELETE /products/:id - Excluir produto
 */
app.delete('/products/:id', authenticateToken, async (req, res) => {
    try {
        const { id } = req.params;

        const product = await pool.query('SELECT * FROM products WHERE id = $1', [id]);
        if (product.rows.length === 0) {
            return res.status(404).json({ error: 'Produto não encontrado' });
        }

        // Registrar no histórico antes de excluir
        await pool.query(
            'INSERT INTO history (product_id, action, quantity, user_id, product_name, total_value) VALUES ($1, $2, $3, $4, $5, $6)',
            [id, 'exclusao', 0, req.user.id, product.rows[0].name, 0]
        );

        await pool.query('DELETE FROM products WHERE id = $1', [id]);

        res.json({ message: 'Produto excluído com sucesso' });

    } catch (error) {
        console.error('Erro ao excluir produto:', error);
        res.status(500).json({ error: 'Erro interno do servidor' });
    }
});

// ====================================================================================
// ROTAS DE MOVIMENTAÇÃO DE ESTOQUE
// ====================================================================================

/**
 * PUT /products/:id/increase - Entrada de estoque
 */
app.put('/products/:id/increase', authenticateToken, async (req, res) => {
    try {
        const { id } = req.params;
        const { quantity } = req.body;

        const qty = parseInt(quantity);
        if (!qty || qty <= 0) {
            return res.status(400).json({ error: 'Quantidade inválida' });
        }

        const product = await pool.query('SELECT * FROM products WHERE id = $1', [id]);
        if (product.rows.length === 0) {
            return res.status(404).json({ error: 'Produto não encontrado' });
        }

        const result = await pool.query(
            'UPDATE products SET quantity = quantity + $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2 RETURNING *',
            [qty, id]
        );

        const updatedProduct = result.rows[0];
        
        const price = parseFloat(product.rows[0].price) || 0;
        const totalValue = qty * price;

        await pool.query(
            'INSERT INTO history (product_id, action, quantity, user_id, product_name, total_value) VALUES ($1, $2, $3, $4, $5, $6)',
            [id, 'entrada', qty, req.user.id, product.rows[0].name, totalValue]
        );

        res.json({
            ...updatedProduct,
            quantity: parseInt(updatedProduct.quantity) || 0,
            price: parseFloat(updatedProduct.price) || 0
        });

    } catch (error) {
        console.error('Erro ao aumentar estoque:', error);
        res.status(500).json({ error: 'Erro interno do servidor' });
    }
});

/**
 * PUT /products/:id/decrease - Saída de estoque
 */
app.put('/products/:id/decrease', authenticateToken, async (req, res) => {
    try {
        const { id } = req.params;
        const { quantity } = req.body;

        const qty = parseInt(quantity);
        if (!qty || qty <= 0) {
            return res.status(400).json({ error: 'Quantidade inválida' });
        }

        const product = await pool.query('SELECT * FROM products WHERE id = $1', [id]);
        if (product.rows.length === 0) {
            return res.status(404).json({ error: 'Produto não encontrado' });
        }

        const currentQty = parseInt(product.rows[0].quantity) || 0;
        if (currentQty < qty) {
            return res.status(400).json({ error: 'Estoque insuficiente' });
        }

        const result = await pool.query(
            'UPDATE products SET quantity = quantity - $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2 RETURNING *',
            [qty, id]
        );

        const updatedProduct = result.rows[0];

        const price = parseFloat(product.rows[0].price) || 0;
        const totalValue = qty * price;

        await pool.query(
            'INSERT INTO history (product_id, action, quantity, user_id, product_name, total_value) VALUES ($1, $2, $3, $4, $5, $6)',
            [id, 'saida', qty, req.user.id, product.rows[0].name, totalValue]
        );

        res.json({
            ...updatedProduct,
            quantity: parseInt(updatedProduct.quantity) || 0,
            price: parseFloat(updatedProduct.price) || 0
        });

    } catch (error) {
        console.error('Erro ao diminuir estoque:', error);
        res.status(500).json({ error: 'Erro interno do servidor' });
    }
});

// ====================================================================================
// ROTAS DE HISTÓRICO
// ====================================================================================

app.get('/history', authenticateToken, async (req, res) => {
    try {
        const { date, action } = req.query;
        let query = `
            SELECT h.*, u.name as user_name 
            FROM history h 
            LEFT JOIN users u ON h.user_id = u.id
        `;
        let params = [];
        let conditions = [];

        if (date) {
            conditions.push(`DATE(h.date) = $${params.length + 1}`);
            params.push(date);
        }

        if (action) {
            conditions.push(`h.action = $${params.length + 1}`);
            params.push(action);
        }

        if (conditions.length > 0) {
            query += ' WHERE ' + conditions.join(' AND ');
        }

        query += ' ORDER BY h.date DESC LIMIT 100';

        const result = await pool.query(query, params);
        
        const formattedHistory = result.rows.map(h => ({
            ...h,
            created_at: h.date,
            type: h.action,
            total_value: parseFloat(h.total_value) || 0
        }));
        
        res.json(formattedHistory);

    } catch (error) {
        console.error('Erro ao listar histórico:', error);
        res.status(500).json({ error: 'Erro interno do servidor' });
    }
});

// ====================================================================================
// ROTAS DE DASHBOARD
// ====================================================================================

app.get('/dashboard', authenticateToken, async (req, res) => {
    try {
        const totalProducts = await pool.query('SELECT COUNT(*) as count FROM products');
        const lowStock = await pool.query('SELECT COUNT(*) as count FROM products WHERE quantity <= COALESCE(min_quantity, 5)');
        const totalValue = await pool.query('SELECT COALESCE(SUM(quantity * price), 0) as total FROM products');
        const totalItems = await pool.query('SELECT COALESCE(SUM(quantity), 0) as total FROM products');

        const entriesToday = await pool.query(`
            SELECT COUNT(*) as count 
            FROM history 
            WHERE action = 'entrada' AND DATE(date) = CURRENT_DATE
        `);

        const exitsToday = await pool.query(`
            SELECT COUNT(*) as count 
            FROM history 
            WHERE action = 'saida' AND DATE(date) = CURRENT_DATE
        `);

        res.json({
            totalProducts: parseInt(totalProducts.rows[0].count) || 0,
            lowStock: parseInt(lowStock.rows[0].count) || 0,
            totalValue: parseFloat(totalValue.rows[0].total) || 0,
            totalItems: parseInt(totalItems.rows[0].total) || 0,
            entriesToday: parseInt(entriesToday.rows[0].count) || 0,
            exitsToday: parseInt(exitsToday.rows[0].count) || 0
        });

    } catch (error) {
        console.error('Erro ao carregar dashboard:', error);
        res.status(500).json({ error: 'Erro interno do servidor' });
    }
});

// ====================================================================================
// ROTAS DE USUÁRIOS (ADMIN)
// ====================================================================================

app.get('/users', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT id, name, email, role, created_at FROM users ORDER BY name ASC'
        );
        res.json(result.rows);

    } catch (error) {
        console.error('Erro ao listar usuários:', error);
        res.status(500).json({ error: 'Erro interno do servidor' });
    }
});

app.delete('/users/:id', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { id } = req.params;

        if (parseInt(id) === req.user.id) {
            return res.status(400).json({ error: 'Não é possível excluir seu próprio usuário' });
        }

        const result = await pool.query('DELETE FROM users WHERE id = $1 RETURNING *', [id]);
        
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Usuário não encontrado' });
        }

        res.json({ message: 'Usuário excluído com sucesso' });

    } catch (error) {
        console.error('Erro ao excluir usuário:', error);
        res.status(500).json({ error: 'Erro interno do servidor' });
    }
});

// ====================================================================================
// ROTA PRINCIPAL
// ====================================================================================

app.get('/', (req, res) => {
    res.json({
        message: 'StockFlow API',
        version: '2.1.0',
        status: 'online',
        timestamp: new Date().toISOString()
    });
});

// ====================================================================================
// INICIALIZAÇÃO DO SERVIDOR
// ====================================================================================

const PORT = process.env.PORT || 5000;

app.listen(PORT, async () => {
    console.log('🚀 StockFlow API v2.1 iniciando...');
    console.log(`📡 Porta: ${PORT}`);
    console.log(`🌍 Ambiente: ${process.env.NODE_ENV || 'development'}`);
    
    try {
        await initializeDatabase();
        console.log(`✅ Servidor rodando em http://localhost:${PORT}`);
    } catch (error) {
        console.error('❌ Erro fatal ao iniciar servidor:', error);
        process.exit(1);
    }
});

module.exports = app;