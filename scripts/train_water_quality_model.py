import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
import joblib
import mysql.connector
from datetime import datetime, timedelta
import warnings
warnings.filterwarnings('ignore')

# Database configuration
db_config = {
    "host": "localhost",
    "user": "root", 
    "password": "",
    "database": "vcrab_db_final"
}

def get_db_connection():
    try:
        return mysql.connector.connect(**db_config)
    except mysql.connector.Error as e:
        print("Database connection error:", e)
        return None

def generate_training_data():
    """Generate synthetic training data based on sensor parameters"""
    np.random.seed(42)
    
    # Optimal ranges for crab farming
    optimal_ranges = {
        'temperature': (25, 30),    # 25-30°C
        'ph_level': (6.5, 8.5),     # 6.5-8.5 pH
        'tds_value': (50, 1000),    # 50-1000 ppm
        'turbidity': (10, 30)       # 10-30 NTU
    }
    
    # Generate 5000 training samples
    n_samples = 5000
    data = []
    
    for i in range(n_samples):
        # Generate base values with some correlation
        temp = np.random.normal(27.5, 2.5)  # Mean 27.5°C
        ph = np.random.normal(7.5, 0.8)     # Mean 7.5 pH
        tds = np.random.normal(525, 200)    # Mean 525 ppm
        turbidity = np.random.normal(20, 8) # Mean 20 NTU
        
        # Add some realistic correlations
        if temp > 29:  # High temperature affects other parameters
            ph += np.random.normal(0, 0.2)
            turbidity += np.random.normal(2, 1)
        
        if ph < 6.8 or ph > 8.2:  # pH extremes affect TDS
            tds += np.random.normal(50, 25)
        
        # Determine water quality status
        status = determine_water_quality_status(temp, ph, tds, turbidity, optimal_ranges)
        
        data.append({
            'temperature': round(temp, 2),
            'ph_level': round(ph, 2),
            'tds_value': round(tds, 2),
            'turbidity': round(turbidity, 2),
            'quality_status': status,
            'timestamp': datetime.now() - timedelta(days=np.random.randint(0, 365))
        })
    
    return pd.DataFrame(data)

def determine_water_quality_status(temp, ph, tds, turbidity, ranges):
    """Determine water quality status based on sensor readings"""
    critical_count = 0
    warning_count = 0
    
    # Temperature assessment
    if temp < ranges['temperature'][0] - 2 or temp > ranges['temperature'][1] + 2:
        critical_count += 1
    elif temp < ranges['temperature'][0] or temp > ranges['temperature'][1]:
        warning_count += 1
    
    # pH assessment
    if ph < ranges['ph_level'][0] - 0.5 or ph > ranges['ph_level'][1] + 0.5:
        critical_count += 1
    elif ph < ranges['ph_level'][0] or ph > ranges['ph_level'][1]:
        warning_count += 1
    
    # TDS assessment
    if tds < ranges['tds_value'][0] - 50 or tds > ranges['tds_value'][1] + 200:
        critical_count += 1
    elif tds < ranges['tds_value'][0] or tds > ranges['tds_value'][1]:
        warning_count += 1
    
    # Turbidity assessment
    if turbidity < ranges['turbidity'][0] - 5 or turbidity > ranges['turbidity'][1] + 10:
        critical_count += 1
    elif turbidity < ranges['turbidity'][0] or turbidity > ranges['turbidity'][1]:
        warning_count += 1
    
    # Determine overall status
    if critical_count >= 2:
        return 'Critical'
    elif critical_count >= 1 or warning_count >= 2:
        return 'Warning'
    else:
        return 'Safe'

def train_models():
    """Train multiple ML models for water quality prediction"""
    print("🔄 Generating training data...")
    df = generate_training_data()
    
    # Prepare features and target
    features = ['temperature', 'ph_level', 'tds_value', 'turbidity']
    X = df[features]
    y = df['quality_status']
    
    print(f"📊 Training data shape: {X.shape}")
    print(f"📈 Class distribution:\n{y.value_counts()}")
    
    # Split data
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    
    # Scale features
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
    # Train Random Forest
    print("\n🌲 Training Random Forest...")
    rf_model = RandomForestClassifier(
        n_estimators=100,
        max_depth=10,
        min_samples_split=5,
        min_samples_leaf=2,
        random_state=42
    )
    rf_model.fit(X_train_scaled, y_train)
    
    # Train Gradient Boosting
    print("🚀 Training Gradient Boosting...")
    gb_model = GradientBoostingClassifier(
        n_estimators=100,
        learning_rate=0.1,
        max_depth=6,
        random_state=42
    )
    gb_model.fit(X_train_scaled, y_train)
    
    # Evaluate models
    models = {
        'RandomForest': rf_model,
        'GradientBoosting': gb_model
    }
    
    best_model = None
    best_score = 0
    
    print("\n📊 Model Evaluation:")
    print("-" * 50)
    
    for name, model in models.items():
        # Predictions
        y_pred = model.predict(X_test_scaled)
        accuracy = accuracy_score(y_test, y_pred)
        
        # Cross-validation
        cv_scores = cross_val_score(model, X_train_scaled, y_train, cv=5)
        
        print(f"\n{name}:")
        print(f"  Accuracy: {accuracy:.4f}")
        print(f"  CV Score: {cv_scores.mean():.4f} (+/- {cv_scores.std() * 2:.4f})")
        
        # Feature importance for tree-based models
        if hasattr(model, 'feature_importances_'):
            importance = model.feature_importances_
            print("  Feature Importance:")
            for i, feature in enumerate(features):
                print(f"    {feature}: {importance[i]:.4f}")
        
        if accuracy > best_score:
            best_score = accuracy
            best_model = model
            best_model_name = name
    
    print(f"\n🏆 Best Model: {best_model_name} (Accuracy: {best_score:.4f})")
    
    # Save models and scaler
    print("\n💾 Saving models...")
    joblib.dump(best_model, 'models/water_quality_model.pkl')
    joblib.dump(scaler, 'models/water_quality_scaler.pkl')
    joblib.dump(features, 'models/feature_names.pkl')
    
    # Save model metadata
    metadata = {
        'model_type': best_model_name,
        'accuracy': best_score,
        'features': features,
        'training_date': datetime.now().isoformat(),
        'training_samples': len(X_train)
    }
    joblib.dump(metadata, 'models/model_metadata.pkl')
    
    print("✅ Model training completed successfully!")
    return best_model, scaler, metadata

def store_training_data_in_db():
    """Store some training data in database for reference"""
    conn = get_db_connection()
    if not conn:
        print("❌ Could not connect to database")
        return
    
    cursor = conn.cursor()
    
    # Create training data table if not exists
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS ml_training_data (
            id INT AUTO_INCREMENT PRIMARY KEY,
            temperature DECIMAL(5,2),
            ph_level DECIMAL(4,2),
            tds_value DECIMAL(8,2),
            turbidity DECIMAL(6,2),
            quality_status VARCHAR(20),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    # Generate and insert sample data
    df = generate_training_data()
    sample_data = df.sample(n=100)  # Store 100 samples
    
    for _, row in sample_data.iterrows():
        cursor.execute("""
            INSERT INTO ml_training_data (temperature, ph_level, tds_value, turbidity, quality_status)
            VALUES (%s, %s, %s, %s, %s)
        """, (row['temperature'], row['ph_level'], row['tds_value'], row['turbidity'], row['quality_status']))
    
    conn.commit()
    cursor.close()
    conn.close()
    print("✅ Training data stored in database")

if __name__ == "__main__":
    import os
    
    # Create models directory
    os.makedirs('models', exist_ok=True)
    
    print("🤖 Starting Water Quality ML Model Training")
    print("=" * 60)
    
    # Train models
    model, scaler, metadata = train_models()
    
    # Store training data
    store_training_data_in_db()
    
    print("\n🎉 Training process completed!")
    print(f"📁 Models saved in 'models/' directory")
    print(f"🎯 Best model accuracy: {metadata['accuracy']:.4f}")
