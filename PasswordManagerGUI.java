import javax.crypto.*;
import javax.crypto.spec.*;
import javax.swing.*;
import javax.swing.table.DefaultTableModel;

import java.awt.*;
import java.awt.event.*;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.KeySpec;
import java.sql.*;
import java.util.Base64;
import java.util.Vector;

public class PasswordManagerGUI extends JFrame {

    private static final String DB_FILE = "passwords.db";
    private static final String AES_TRANSFORMATION = "AES/CBC/PKCS5Padding";
    private static final String KEY_FACTORY_ALGORITHM = "PBKDF2WithHmacSHA256";
    private static final int KEY_SIZE = 256;
    private static final int ITERATIONS = 65536;
    private static final int SALT_LENGTH = 16;
    private static final int IV_LENGTH = 16;

    private JTextField siteField, userField, searchField;
    private JPasswordField passwordField, masterPasswordField;
    private JButton addButton, searchButton, deleteButton, showAllButton, unlockButton;
    private JTable table;
    private DefaultTableModel tableModel;

    private SecretKey masterKey;
    private Connection conn;

    public PasswordManagerGUI() {
        setTitle("Password Manager");
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setSize(800, 500);
        setLocationRelativeTo(null);

        initComponents();
        layoutComponents();

        try {
            connectDatabase();
            createTableIfNotExists();
            toggleControls(false);
        } catch (Exception e) {
            e.printStackTrace();
            JOptionPane.showMessageDialog(this, "Database error: " + e.getMessage());
            System.exit(1);
        }
    }

    private void initComponents() {
        siteField = new JTextField(15);
        userField = new JTextField(15);
        passwordField = new JPasswordField(15);
        searchField = new JTextField(15);
        masterPasswordField = new JPasswordField(15);

        addButton = new JButton("Add Credential");
        searchButton = new JButton("Search");
        deleteButton = new JButton("Delete Selected");
        showAllButton = new JButton("Show All");
        unlockButton = new JButton("Unlock");

        tableModel = new DefaultTableModel(new Object[]{"ID", "Site", "Username", "Password"}, 0) {
            // Make ID column hidden later or non-editable
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };
        table = new JTable(tableModel);
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);

        // Button listeners
        unlockButton.addActionListener(e -> unlockDatabase());
        addButton.addActionListener(e -> addCredential());
        searchButton.addActionListener(e -> searchCredentials());
        deleteButton.addActionListener(e -> deleteSelectedCredential());
        showAllButton.addActionListener(e -> showAllCredentials());
    }

    private void layoutComponents() {
        JPanel topPanel = new JPanel(new FlowLayout());
        topPanel.add(new JLabel("Master Password:"));
        topPanel.add(masterPasswordField);
        topPanel.add(unlockButton);

        JPanel inputPanel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();

        gbc.insets = new Insets(4,4,4,4);
        gbc.gridx = 0; gbc.gridy = 0; inputPanel.add(new JLabel("Site:"), gbc);
        gbc.gridx = 1; inputPanel.add(siteField, gbc);
        gbc.gridx = 0; gbc.gridy = 1; inputPanel.add(new JLabel("Username:"), gbc);
        gbc.gridx = 1; inputPanel.add(userField, gbc);
        gbc.gridx = 0; gbc.gridy = 2; inputPanel.add(new JLabel("Password:"), gbc);
        gbc.gridx = 1; inputPanel.add(passwordField, gbc);

        gbc.gridx = 0; gbc.gridy = 3; gbc.gridwidth = 2;
        inputPanel.add(addButton, gbc);

        JPanel searchPanel = new JPanel(new FlowLayout());
        searchPanel.add(new JLabel("Search Site:"));
        searchPanel.add(searchField);
        searchPanel.add(searchButton);
        searchPanel.add(deleteButton);
        searchPanel.add(showAllButton);

        JScrollPane tableScroll = new JScrollPane(table);

        Container container = getContentPane();
        container.setLayout(new BorderLayout());
        container.add(topPanel, BorderLayout.NORTH);
        container.add(inputPanel, BorderLayout.WEST);
        container.add(searchPanel, BorderLayout.SOUTH);
        container.add(tableScroll, BorderLayout.CENTER);
    }

    private void connectDatabase() throws SQLException {
        File dbFile = new File(DB_FILE);
        String url = "jdbc:sqlite:" + db_FILE;
        conn = DriverManager.getConnection(url);
    }

    private void createTableIfNotExists() throws SQLException {
        String sql = "CREATE TABLE IF NOT EXISTS credentials (" +
                     "id INTEGER PRIMARY KEY AUTOINCREMENT," +
                     "site TEXT NOT NULL," +
                     "username TEXT NOT NULL," +
                     "salt TEXT NOT NULL," +
                     "iv TEXT NOT NULL," +
                     "password TEXT NOT NULL)";
        try (Statement stmt = conn.createStatement()) {
            stmt.execute(sql);
        }
    }

    private void toggleControls(boolean enabled) {
        siteField.setEnabled(enabled);
        userField.setEnabled(enabled);
        passwordField.setEnabled(enabled);
        addButton.setEnabled(enabled);
        searchField.setEnabled(enabled);
        searchButton.setEnabled(enabled);
        deleteButton.setEnabled(enabled);
        showAllButton.setEnabled(enabled);
        table.setEnabled(enabled);
    }

    private SecretKey getKeyFromPassword(String password, byte[] salt) throws Exception {
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, ITERATIONS, KEY_SIZE);
        SecretKeyFactory factory = SecretKeyFactory.getInstance(KEY_FACTORY_ALGORITHM);
        byte[] keyBytes = factory.generateSecret(spec).getEncoded();
        return new SecretKeySpec(keyBytes, "AES");
    }

    private void unlockDatabase() {
        String masterPass = new String(masterPasswordField.getPassword());
        if (masterPass.isEmpty()) {
            JOptionPane.showMessageDialog(this, "Please enter master password.");
            return;
        }
        try {
            // For unlocking, we'll try to decrypt one credential (if any) to verify key
            // Or create masterKey from masterPass and fixed salt (we’ll store salt in file or static here)
            // Here for demo, use a fixed salt for master key (better: store salt securely)
            byte[] masterSalt = "MasterSalt123456".getBytes(StandardCharsets.UTF_8);
            masterKey = getKeyFromPassword(masterPass, masterSalt);

            if (!verifyMasterPassword()) {
                JOptionPane.showMessageDialog(this, "Incorrect master password or no data yet.");
                return;
            }

            toggleControls(true);
            unlockButton.setEnabled(false);
            masterPasswordField.setEnabled(false);
            showAllCredentials();

        } catch (Exception ex) {
            ex.printStackTrace();
            JOptionPane.showMessageDialog(this, "Error unlocking database: " + ex.getMessage());
        }
    }

    private boolean verifyMasterPassword() throws Exception {
        String sql = "SELECT salt, iv, password FROM credentials LIMIT 1";
        try (PreparedStatement pstmt = conn.prepareStatement(sql);
             ResultSet rs = pstmt.executeQuery()) {
            if (rs.next()) {
                byte[] salt = Base64.getDecoder().decode(rs.getString("salt"));
                byte[] iv = Base64.getDecoder().decode(rs.getString("iv"));
                String encryptedPwd = rs.getString("password");

                SecretKey key = getKeyFromPassword(new String(masterPasswordField.getPassword()), salt);
                decrypt(encryptedPwd, key, iv);  // throws if password is invalid
            }
        }
        return true; // no data yet or decryption succeeded
    }

    private void addCredential() {
        String site = siteField.getText().trim();
        String username = userField.getText().trim();
        String password = new String(passwordField.getPassword());

        if (site.isEmpty() || username.isEmpty() || password.isEmpty()) {
            JOptionPane.showMessageDialog(this, "Please fill in all fields.");
            return;
        }
        try {
            // Generate random salt & iv per entry
            byte[] salt = generateRandomBytes(SALT_LENGTH);
            byte[] iv = generateRandomBytes(IV_LENGTH);
            SecretKey key = getKeyFromPassword(new String(masterPasswordField.getPassword()), salt);

            String encryptedPwd = encrypt(password, key, iv);

            String sql = "INSERT INTO credentials(site, username, salt, iv, password) VALUES (?, ?, ?, ?, ?)";
            try (PreparedStatement pstmt = conn.prepareStatement(sql)) {
                pstmt.setString(1, site);
                pstmt.setString(2, username);
                pstmt.setString(3, Base64.getEncoder().encodeToString(salt));
                pstmt.setString(4, Base64.getEncoder().encodeToString(iv));
                pstmt.setString(5, encryptedPwd);
                pstmt.executeUpdate();
            }
            JOptionPane.showMessageDialog(this, "Credential saved.");
            clearInputFields();
            showAllCredentials();
        } catch (Exception e) {
            e.printStackTrace();
            JOptionPane.showMessageDialog(this, "Error saving credential: " + e.getMessage());
        }
    }

    private void searchCredentials() {
        String siteSearch = searchField.getText().trim();
        if (siteSearch.isEmpty()) {
            JOptionPane.showMessageDialog(this, "Enter site to search.");
            return;
        }
        try {
            String sql = "SELECT id, site, username, salt, iv, password FROM credentials WHERE site LIKE ?";
            try (PreparedStatement pstmt = conn.prepareStatement(sql)) {
                pstmt.setString(1, "%" + siteSearch + "%");
                try (ResultSet rs = pstmt.executeQuery()) {
                    populateTable(rs);
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
            JOptionPane.showMessageDialog(this, "Search error: " + e.getMessage());
        }
    }

    private void deleteSelectedCredential() {
        int selectedRow = table.getSelectedRow();
        if (selectedRow == -1) {
            JOptionPane.showMessageDialog(this, "Select a credential to delete.");
            return;
        }
        int confirm = JOptionPane.showConfirmDialog(this, "Delete selected credential?", "Confirm", JOptionPane.YES_NO_OPTION);
        if (confirm != JOptionPane.YES_OPTION) return;

        int id = (int) tableModel.getValueAt(selectedRow, 0);
        try {
            String sql = "DELETE FROM credentials WHERE id=?";
            try (PreparedStatement pstmt = conn.prepareStatement(sql)) {
                pstmt.setInt(1, id);
                pstmt.executeUpdate();
            }
            JOptionPane.showMessageDialog(this, "Credential deleted.");
            showAllCredentials();
        } catch (SQLException e) {
            e.printStackTrace();
            JOptionPane.showMessageDialog(this, "Delete error: " + e.getMessage());
        }
    }

    private void showAllCredentials() {
        try {
            String sql = "SELECT id, site, username, salt, iv, password FROM credentials";
            try (PreparedStatement pstmt = conn.prepareStatement(sql);
                 ResultSet rs = pstmt.executeQuery()) {
                populateTable(rs);
            }
        } catch (Exception e) {
            e.printStackTrace();
            JOptionPane.showMessageDialog(this, "Error loading credentials: " + e.getMessage());
        }
    }

    private void populateTable(ResultSet rs) throws Exception {
        tableModel.setRowCount(0);
        while (rs.next()) {
            int id = rs.getInt("id");
            String site = rs.getString("site");
            String username = rs.getString("username");
            byte[] salt = Base64.getDecoder().decode(rs.getString("salt"));
            byte[] iv = Base64.getDecoder().decode(rs.getString("iv"));
            String encryptedPwd = rs.getString("password");

            SecretKey key = getKeyFromPassword(new String(masterPasswordField.getPassword()), salt);
            String decryptedPwd = decrypt(encryptedPwd, key, iv);

            Vector<Object> row = new Vector<>();
            row.add(id);
            row.add(site);
            row.add(username);
            row.add(decryptedPwd);
            tableModel.addRow(row);
        }
    }

    private void clearInputFields() {
        siteField.setText("");
        userField.setText("");
        passwordField.setText("");
    }

    private byte[] generateRandomBytes(int length) {
        byte[] bytes = new byte[length];
        new SecureRandom().nextBytes(bytes);
        return bytes;
    }

    private String encrypt(String plainText, SecretKey key, byte[] ivBytes) throws Exception {
        Cipher cipher = Cipher.getInstance(AES_TRANSFORMATION);
        IvParameterSpec iv = new IvParameterSpec(ivBytes);
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        byte[] encrypted = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encrypted);
    }

    private String decrypt(String cipherText, SecretKey key, byte[] ivBytes) throws Exception {
        Cipher cipher = Cipher.getInstance(AES_TRANSFORMATION);
        IvParameterSpec iv = new IvParameterSpec(ivBytes);
        cipher.init(Cipher.DECRYPT_MODE, key, iv);
        byte[] decoded = Base64.getDecoder().decode(cipherText);
        byte[] decrypted = cipher.doFinal(decoded);
        return new String(decrypted, StandardCharsets.UTF_8);
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            new PasswordManagerGUI().setVisible(true);
        });
    }
}
