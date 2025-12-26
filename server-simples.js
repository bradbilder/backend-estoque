// ====================================
// STOCKFLOW - BACKEND SUPER SIMPLES
// ====================================

const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const sqlite3 = require('sqlite3').verbose();

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'minha-chave-secreta-123';

// Middleware
app.use(cors());
app.use(express.json());

// ====================================
// BANCO DE DADOS SQLITE (arquivo local)
// ====================================
const db = new sqlite3.Database('./estoque.db', (err) => {
    if (err) {
        console.error('❌ Erro ao conectar banco:', err);
    } else {
        console.log('✅ Banco SQLite conectado!');
        inicializarBanco();
    }
});

// Criar tabelas
function inicializarBanco() {
    db.serialize(() => {
        // Tabela de usuários
        db.run(`
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                role TEXT DEFAULT 'funcionario',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        `);

        // Tabela de produtos
        db.run(`
            CREATE TABLE IF NOT EXISTS products (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                barcode TEXT UNIQUE,
                quantity INTEGER DEFAULT 0,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        `);

        // Tabela de histórico
        db.run(`
            CREATE TABLE IF NOT EXISTS history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                product_id INTEGER,
                product_name TEXT,
                action TEXT NOT NULL,
                quantity INTEGER DEFAULT 0,
                user_id INTEGER,
                date DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (product_id) REFERENCES products(id),
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        `);

        // Criar admin padrão
        db.get('SELECT * FROM users WHERE email = ?', ['admin@estoque.com'], (err, row) => {
            if (!row) {
                const senha = bcrypt.hashSync('admin123', 10);
                db.run(
                    'INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)',
                    ['Administrador', 'admin@estoque.com', senha, 'admin'],
                    () => {
                        console.log('👤 Admin criado: admin@estoque.com / admin123');
                    }
                );
            }
        });
    });
}

// ====================================
// MIDDLEWARE DE AUTENTICAÇÃO
// ====================================
function autenticar(req, res, next) {
    const token = req.headers['authorization']?.split(' ')[1];
    
    if (!token) {
        return res.status(401).json({ error: 'Token não fornecido' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Token inválido' });
        }
        req.user = user;
        next();
    });
}

// ====================================
// ROTAS DE AUTENTICAÇÃO
// ====================================

// Registrar usuário
app.post('/auth/register', (req, res) => {
    const { name, email, password, role = 'funcionario' } = req.body;

    if (!name || !email || !password) {
        return res.status(400).json({ error: 'Preencha todos os campos' });
    }

    const senhaHash = bcrypt.hashSync(password, 10);

    db.run(
        'INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)',
        [name, email, senhaHash, role],
        function(err) {
            if (err) {
                return res.status(400).json({ error: 'Email já cadastrado' });
            }

            const token = jwt.sign({ id: this.lastID, email, role }, JWT_SECRET, { expiresIn: '7d' });

            res.status(201).json({
                token,
                user: { id: this.lastID, name, email, role }
            });
        }
    );
});

// Login
app.post('/auth/login', (req, res) => {
    const { email, password } = req.body;

    db.get('SELECT * FROM users WHERE email = ?', [email], (err, user) => {
        if (!user) {
            return res.status(401).json({ error: 'Email ou senha inválidos' });
        }

        if (!bcrypt.compareSync(password, user.password)) {
            return res.status(401).json({ error: 'Email ou senha inválidos' });
        }

        const token = jwt.sign(
            { id: user.id, email: user.email, role: user.role },
            JWT_SECRET,
            { expiresIn: '7d' }
        );

        res.json({
            token,
            user: {
                id: user.id,
                name: user.name,
                email: user.email,
                role: user.role
            }
        });
    });
});

// ====================================
// ROTAS DE PRODUTOS
// ====================================

// Listar produtos
app.get('/products', autenticar, (req, res) => {
    const { search, barcode } = req.query;
    let query = 'SELECT * FROM products';
    let params = [];

    if (search) {
        query += ' WHERE name LIKE ?';
        params.push(`%${search}%`);
    } else if (barcode) {
        query += ' WHERE barcode = ?';
        params.push(barcode);
    }

    query += ' ORDER BY name';

    db.all(query, params, (err, rows) => {
        if (err) {
            return res.status(500).json({ error: 'Erro ao buscar produtos' });
        }
        res.json(rows);
    });
});

// Criar produto
app.post('/products', autenticar, (req, res) => {
    const { name, barcode, quantity = 0 } = req.body;

    if (!name) {
        return res.status(400).json({ error: 'Nome é obrigatório' });
    }

    db.run(
        'INSERT INTO products (name, barcode, quantity) VALUES (?, ?, ?)',
        [name, barcode, quantity],
        function(err) {
            if (err) {
                return res.status(400).json({ error: 'Código de barras já cadastrado' });
            }

            const productId = this.lastID;

            // Registrar no histórico
            if (quantity > 0) {
                db.run(
                    'INSERT INTO history (product_id, product_name, action, quantity, user_id) VALUES (?, ?, ?, ?, ?)',
                    [productId, name, 'cadastro', quantity, req.user.id]
                );
            }

            res.status(201).json({
                id: productId,
                name,
                barcode,
                quantity
            });
        }
    );
});

// Atualizar produto
app.put('/products/:id', autenticar, (req, res) => {
    const { id } = req.params;
    const { name, barcode, quantity } = req.body;

    db.run(
        'UPDATE products SET name = ?, barcode = ?, quantity = ? WHERE id = ?',
        [name, barcode, quantity, id],
        function(err) {
            if (err) {
                return res.status(400).json({ error: 'Erro ao atualizar' });
            }

            // Registrar no histórico
            db.run(
                'INSERT INTO history (product_id, product_name, action, quantity, user_id) VALUES (?, ?, ?, ?, ?)',
                [id, name, 'edicao', quantity, req.user.id]
            );

            res.json({ id, name, barcode, quantity });
        }
    );
});

// Deletar produto
app.delete('/products/:id', autenticar, (req, res) => {
    const { id } = req.params;

    db.get('SELECT name FROM products WHERE id = ?', [id], (err, product) => {
        if (!product) {
            return res.status(404).json({ error: 'Produto não encontrado' });
        }

        // Registrar exclusão
        db.run(
            'INSERT INTO history (product_id, product_name, action, quantity, user_id) VALUES (?, ?, ?, ?, ?)',
            [id, product.name, 'exclusao', 0, req.user.id]
        );

        db.run('DELETE FROM products WHERE id = ?', [id], (err) => {
            if (err) {
                return res.status(500).json({ error: 'Erro ao excluir' });
            }
            res.json({ message: 'Produto excluído' });
        });
    });
});

// Aumentar estoque (entrada)
app.put('/products/:id/increase', autenticar, (req, res) => {
    const { id } = req.params;
    const { quantity } = req.body;

    db.get('SELECT * FROM products WHERE id = ?', [id], (err, product) => {
        if (!product) {
            return res.status(404).json({ error: 'Produto não encontrado' });
        }

        const novaQuantidade = product.quantity + quantity;

        db.run(
            'UPDATE products SET quantity = ? WHERE id = ?',
            [novaQuantidade, id],
            () => {
                // Registrar no histórico
                db.run(
                    'INSERT INTO history (product_id, product_name, action, quantity, user_id) VALUES (?, ?, ?, ?, ?)',
                    [id, product.name, 'entrada', quantity, req.user.id]
                );

                res.json({ ...product, quantity: novaQuantidade });
            }
        );
    });
});

// Diminuir estoque (saída)
app.put('/products/:id/decrease', autenticar, (req, res) => {
    const { id } = req.params;
    const { quantity } = req.body;

    db.get('SELECT * FROM products WHERE id = ?', [id], (err, product) => {
        if (!product) {
            return res.status(404).json({ error: 'Produto não encontrado' });
        }

        if (product.quantity < quantity) {
            return res.status(400).json({ error: 'Estoque insuficiente' });
        }

        const novaQuantidade = product.quantity - quantity;

        db.run(
            'UPDATE products SET quantity = ? WHERE id = ?',
            [novaQuantidade, id],
            () => {
                // Registrar no histórico
                db.run(
                    'INSERT INTO history (product_id, product_name, action, quantity, user_id) VALUES (?, ?, ?, ?, ?)',
                    [id, product.name, 'saida', quantity, req.user.id]
                );

                res.json({ ...product, quantity: novaQuantidade });
            }
        );
    });
});

// ====================================
// ROTAS DE HISTÓRICO
// ====================================

app.get('/history', autenticar, (req, res) => {
    const { date, action } = req.query;
    let query = `
        SELECT h.*, u.name as user_name 
        FROM history h 
        LEFT JOIN users u ON h.user_id = u.id
        WHERE 1=1
    `;
    let params = [];

    if (date) {
        query += ' AND DATE(h.date) = ?';
        params.push(date);
    }

    if (action) {
        query += ' AND h.action = ?';
        params.push(action);
    }

    query += ' ORDER BY h.date DESC';

    db.all(query, params, (err, rows) => {
        if (err) {
            return res.status(500).json({ error: 'Erro ao buscar histórico' });
        }
        res.json(rows);
    });
});

// ====================================
// DASHBOARD
// ====================================

app.get('/dashboard', autenticar, (req, res) => {
    db.get('SELECT COUNT(*) as count FROM products', (err, total) => {
        db.get('SELECT COUNT(*) as count FROM products WHERE quantity < 10', (err, baixo) => {
            db.get('SELECT COUNT(*) as count FROM history WHERE action = "entrada" AND DATE(date) = DATE("now")', (err, entradas) => {
                db.get('SELECT COUNT(*) as count FROM history WHERE action = "saida" AND DATE(date) = DATE("now")', (err, saidas) => {
                    res.json({
                        totalProducts: total.count,
                        lowStock: baixo.count,
                        entriesToday: entradas.count,
                        exitsToday: saidas.count
                    });
                });
            });
        });
    });
});

// ====================================
// USUÁRIOS (ADMIN)
// ====================================

app.get('/users', autenticar, (req, res) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Acesso negado' });
    }

    db.all('SELECT id, name, email, role, created_at FROM users', (err, rows) => {
        if (err) {
            return res.status(500).json({ error: 'Erro ao buscar usuários' });
        }
        res.json(rows);
    });
});

// ====================================
// ROTA RAIZ
// ====================================

app.get('/', (req, res) => {
    res.json({
        message: 'StockFlow API - Rodando!',
        version: '1.0.0',
        endpoints: {
            auth: ['/auth/login', '/auth/register'],
            products: ['/products', '/products/:id/increase', '/products/:id/decrease'],
            history: ['/history'],
            dashboard: ['/dashboard']
        }
    });
});

// ====================================
// INICIAR SERVIDOR
// ====================================

app.listen(PORT, () => {
    console.log('🚀 Servidor rodando em http://localhost:' + PORT);
    console.log('👤 Login: admin@estoque.com / admin123');
});
