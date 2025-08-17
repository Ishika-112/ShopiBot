from dotenv import load_dotenv
load_dotenv()

from flask import Flask,render_template,request,redirect,session,url_for,flash,jsonify
from flask_sqlalchemy import SQLAlchemy
from collections import Counter
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
from flask import make_response
import spacy
nlp = spacy.load("en_core_web_sm")
app = Flask(__name__)
#---for flash messages and session secret key is mandatory----
app.secret_key = "my_secret_key"
import os

app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv(
    "DATABASE_URL",
    "postgresql+psycopg2://shopiuser:StrongPassword!@localhost:5432/shopibot"

)

app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)
with app.app_context():
    db.create_all()

#---defining tables models-----
class Users(db.Model):
    __tablename__ = "users"

    UserName = db.Column(db.String(50), primary_key=True)
    Email = db.Column(db.String(50), nullable=False)
    Password = db.Column(db.String(50), nullable=False)
    Role = db.Column(db.String(50), nullable=False)

class Products(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    category = db.Column(db.String(50), nullable=False)
    price = db.Column(db.Float, nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    availablePacking = db.Column(db.String(50), nullable=False)
    unit = db.Column(db.String(10), nullable=False) 
    description = db.Column(db.String(200), nullable=False)
    available = db.Column(db.Boolean, default=True)
class Orders(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    phone = db.Column(db.String(20))
    address = db.Column(db.String(255))
    payment = db.Column(db.String(50))
    items = db.Column(db.Text)
    total = db.Column(db.Float)
logged_in_users = {}
#----defining routes----
@app.route("/")
def index():
    return redirect(url_for("login"))
#---register page route-----
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"].strip()
        email = request.form["email"].strip()
        password = request.form["password"]
        confirm_password = request.form["confirm_password"]
        if Users.query.filter_by(UserName=username).first():
            flash("You are already registered! Please login.", "error")
            return render_template("register.html")
        if password != confirm_password:
            flash("Passwords do not match.", "error")
            return render_template("register.html")
        is_first_user = Users.query.first() is None
        role = "admin" if is_first_user else "customer"
        user = Users(UserName=username, Email=email, Password=password, Role=role)
        db.session.add(user)
        db.session.commit()
        flash("Successfully Registered. Please login.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")
#---login page route-----
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        user = Users.query.filter_by(UserName=username, Password=password).first()

        if user:
            session["user"] = username
            session["username"]=user.UserName
            session["role"] = user.Role
            logged_in_users[username] = {
        "username": user.UserName,
        "email": user.Email,
    }

            flash("Successfully Logged In", "success")
            if user.Role == "admin":
                return redirect(url_for("admin"))
            else:
                return redirect(url_for("home"))
        else:
            flash("Invalid credentials or not registered!", "error")
            return render_template("index.html")
    return render_template("index.html")
# ---------- Personalized Product Recommendations ----------
def get_user_purchase_history(username):
    orders = Orders.query.filter_by(name=username).all()
    product_names = []

    for order in orders:
        try:
            items = json.loads(order.items) if order.items else []
            for item in items:
                if "name" in item:
                    product_names.append(item["name"])
        except Exception as e:
            print(f"Error decoding order items: {e}")

    return product_names


def train_product_similarity_model():
    products = Products.query.all()
    product_names = [product.name for product in products]
    descriptions = [product.description or "" for product in products]

    tfidf = TfidfVectorizer(stop_words='english')
    tfidf_matrix = tfidf.fit_transform(descriptions)

    similarity_matrix = cosine_similarity(tfidf_matrix)
    return product_names, similarity_matrix


def get_ai_recommendations(user_product_names, product_names, similarity_matrix, top_n=5):
    recommended = set()
    name_to_index = {name: i for i, name in enumerate(product_names)}

    for name in user_product_names:
        if name in name_to_index:
            idx = name_to_index[name]
            sim_scores = list(enumerate(similarity_matrix[idx]))
            sim_scores = sorted(sim_scores, key=lambda x: x[1], reverse=True)

            for i, score in sim_scores[1:top_n+1]:
                recommended.add(product_names[i])

    return list(recommended)


# ---------- Home Route ----------
@app.route("/home")
def home():
    if "user" not in session:
        flash("Please login first!", "error")
        return redirect(url_for("login"))

    username = session["username"]

    # Get user's past orders
    user_orders = Orders.query.filter_by(name=username).all()

    # Count product frequency
    product_count = {}
    for order in user_orders:
        try:
            if order.items:
                items = json.loads(order.items)
                for item in items:
                    name = item.get("name")
                    if name:
                        product_count[name] = product_count.get(name, 0) + 1
        except Exception as e:
            print("Error reading items:", e)

    # Sort and recommend top 5
    sorted_products = sorted(product_count.items(), key=lambda x: x[1], reverse=True)
    top_product_names = [name for name, _ in sorted_products[:5]]

    # Ensure products exist & are available
    recommended_products = Products.query.filter(
        Products.name.in_(top_product_names),
        Products.available == True
    ).all()

    recommended_names = [p.name for p in recommended_products]

    return render_template("home.html", recommendations=recommended_names)
#-----------add from recommendations route-------------------------
@app.route("/add_from_recommendation", methods=["POST"])
def add_from_recommendation():
    if "user" not in session:
        return jsonify({"status": "error", "message": "Please login first"}), 401

    data = request.get_json()
    product_name = data.get("product")
    requested_qty = int(data.get("quantity", 1))
    product = Products.query.filter_by(name=product_name).first()
    
    if not product:
        return jsonify({"status": "error", "message": "Product not found"})

    if not product.available:
        return jsonify({"status": "error", "message": "Product is not available"})

    available_qty = product.quantity
    if requested_qty > available_qty:
        final_qty = available_qty
        status = "adjusted"
        message = f"Only {available_qty} units of '{product_name}' were available, so we added that."
    else:
        final_qty = requested_qty
        status = "success"
        message = f"Added {final_qty} units of '{product_name}' to your cart."

    if final_qty <= 0:
        return jsonify({"status": "error", "message": f"No stock available for '{product_name}'"})

    # Update session cart
    cart = session.get("cart", {})
    pid = str(product.id)
    cart[pid] = cart.get(pid, 0) + final_qty
    session["cart"] = cart
    return jsonify({"status": status, "message": message})

#------add from recommendations completed----------------
#----admin route----
@app.route("/admin")
def admin():
    if "user" not in session or session.get("role") != "admin":
        flash("Unauthorized access! Admins only.", "error")
        return redirect(url_for("home"))

    total_users = Users.query.count()
    total_orders = Orders.query.count()

    LOW_STOCK_LIMIT = 10
    low_stock_products = Products.query.filter(Products.quantity < LOW_STOCK_LIMIT).all()

    # Fetch all orders for the payments table
    orders = Orders.query.all()

    return render_template(
        'admin.html',
        total_users=total_users,
        total_orders=total_orders,
        low_stock_products=low_stock_products,
        orders=orders
    )

#----defining routes for anchor tag------
#----------logout route-----------------
@app.route("/logout")
def logout():
    user = session.get("user")
    if user and user in logged_in_users:
        logged_in_users.pop(user)

    session.clear()
    flash("Logged out successfully", "success")
    return redirect(url_for("login"))
#----------chatbot route----------------------
@app.route("/chatbot")
def chatbot():
    products = Products.query.all()
    return render_template("chatbot.html", products=products)
#---------checkout route------
@app.route("/checkout", methods=["GET", "POST"])
def checkout():
    if request.method == "POST":
        name = request.form.get("name")
        phone = request.form.get("phoneNo")
        address = request.form.get("address")
        payment = request.form.get("paymentMethod")

        cart = session.get("cart", {})
        cart_items = []
        total = 0

        for product_key, quantity in cart.items():
            # product_key looks like: 'Atta (10000 g)'
            if '(' in product_key and product_key.endswith(')'):
                name_part = product_key[:product_key.rfind('(')].strip()
                packing_part = product_key[product_key.rfind('(')+1:-1].strip()

                product = Products.query.filter_by(name=name_part, availablePacking=packing_part).first()
                if product:
                    # Check stock before checkout
                    if product.quantity < quantity:
                        return f"Not enough stock for {product.name}. Only {product.quantity} left.", 400

                    # Reduce stock
                    product.quantity -= quantity

                    subtotal = product.price * quantity
                    cart_items.append({
                        "product_id": product.id,
                        "name": product.name,
                        "price": product.price,
                        "quantity": quantity,
                        "subtotal": subtotal
                    })
                    total += subtotal
                else:
                    return "Product not found in database"
            else:
                return "Invalid product key format"

        db.session.commit()

        
        new_order = Orders(
            name=name,
            phone=phone,
            address=address,
            payment=payment,
            items=json.dumps(cart_items),
            total=total
        )

        db.session.add(new_order)
        db.session.commit()

        
        session['last_order_id'] = new_order.id

        
        session.pop("cart", None)

        return redirect(url_for("bill"))

    return render_template("checkout.html")
#-----------checkout functionality completed---------------
#--------payment route----------------------
@app.route("/payment", methods=["GET", "POST"])
def payment():
    order_id = session.get("last_order_id")
    order = Orders.query.get(order_id)

    if not order:
        return "No order found"

    total_amount = order.total

    # UPI QR Code generate karna
    upi_id = "9215667835@okbizaxis"
    upi_link = f"upi://pay?pa={upi_id}&pn=ShopiBot&am={total_amount}&cu=INR"
    
    qr = qrcode.make(upi_link)
    buf = BytesIO()
    qr.save(buf, format="PNG")
    qr_b64 = base64.b64encode(buf.getvalue()).decode("utf-8")

    if request.method == "POST":
        payment_method = request.form.get("paymentMethod")

        # Cash on Delivery
        if payment_method == "CashOnDelivery":
            order.payment = "Cash on Delivery"
            db.session.commit()
            return redirect(url_for("thankyou"))

        # UPI
        elif payment_method == "upi":
            order.payment = "UPI Payment Initiated"
            db.session.commit()
            return redirect(url_for("thankyou"))

    # GET request → Payment page show karo
    return render_template("payment.html", total_amount=total_amount, qr_code=qr_b64)

#-----payment functionality completed--------------
#------thankyou route-------------
@app.route("/thankyou")
def thankyou():
    return render_template("thankyou.html")
#----- thankyou route completed--------
#---------deleting account route---------------
@app.route("/delete_account", methods=["POST", "GET"])
def delete_account():
    username = session.get("username")
    user = Users.query.filter_by(UserName=username).first()
    
    if user:
        db.session.delete(user)
        db.session.commit()
        session.clear()
        flash("Your account has been deleted successfully.", "success")
        return redirect(url_for("register"))
    else:
        flash("User not found.", "error")
        return redirect(url_for("home"))
#--------chatbot functionality using basic ai------------
import re
def extract_quantity_and_packing(message):
    message = message.lower()

    # Detect packing (size of a single unit)
    packing_pattern = r"\b\d+\s*(kg|g|litre|liter|ml|l)\b"
    packing_match = re.search(packing_pattern, message)
    packing = packing_match.group(0) if packing_match else None

    # Detect quantity (number of units)
    quantity_pattern = r"\b\d+\s*(unit|units|pcs|pieces)?\b"
    quantity_match = re.search(quantity_pattern, message)
    if quantity_match:
        quantity_str = re.search(r"\d+", quantity_match.group(0)).group(0)
        quantity = int(quantity_str)
    else:
        quantity = None

    return quantity, packing
#--------chatbot route-----
@app.route("/chatbot/message", methods=["POST"])
def chat():
    user_message = request.json.get("message", "").lower().strip()
    cart = session.get("cart", {})

    # Optional: Reset session states if user changes intent
    exit_phrases = ["describe", "description", "list", "show me", "tell me about", "category", "products"]
    if any(word in user_message for word in exit_phrases):
        session.pop("pending_quantity_product", None)
        session.pop("pending_quantity_packing", None)
        session.pop("pending_product", None)
        session.pop("pending_packings", None)
        session.pop("pending_removal_product", None)

    # Step 1: Greetings and thanks
    greetings = ["hi", "hello", "hey", "good morning", "good evening"]
    thanks = ["thanks", "thank you", "thankyou", "thanx", "thx"]
    if user_message in greetings:
        return jsonify({"reply": "Hello! How can I help you today?"})
    if user_message in thanks:
        return jsonify({"reply": "You're welcome!"})

    # Step 2: Remove from cart
    if user_message.startswith("remove "):
        pname = user_message.replace("remove", "").replace("from my cart", "").strip().lower()
        pending_removal = [key for key in cart.keys() if pname in key.lower()]
        if len(pending_removal) == 1:
            del cart[pending_removal[0]]
            session["cart"] = cart
            return jsonify({"reply": f"Removed {pname} from your cart."})
        elif len(pending_removal) > 1:
            session["pending_removal_product"] = pname
            options = ', '.join([k.split('(')[-1].strip(')') for k in pending_removal])
            return jsonify({"reply": f"Which packing would you like to remove for {pname}? Available: {options}"})
        elif session.get("pending_removal_product"):
            pending_pname = session["pending_removal_product"]
            packing = user_message.strip()
            for key in list(cart.keys()):
                if pending_pname in key.lower() and packing in key.lower():
                    del cart[key]
                    session["cart"] = cart
                    session.pop("pending_removal_product", None)
                    return jsonify({"reply": f"Removed {key} from your cart."})
        else:
            return jsonify({"reply": f"{pname} is not in your cart."})

    # Step 3: Describe product
    if "describe" in user_message or "description of" in user_message or "tell me about" in user_message:
        pname = (
            user_message.replace("give me", "")
            .replace("description of", "")
            .replace("describe", "")
            .replace("tell me about", "")
            .strip()
        ).lower()
        products = Products.query.all()
        product = next((p for p in products if p.name.lower() == pname), None)
        if product:
            return jsonify({
                "reply": f"{product.name}: {product.description}\nCategory: {product.category}"
            })
        return jsonify({"reply": "Sorry, I couldn't find that product."})

    # Step 4: List products by category
    if any(x in user_message for x in ["list", "show me", "what are the", "see", "give me", "category of", "products in"]):
        products = Products.query.all()
        categories = sorted(set(p.category.strip().lower() for p in products))

        # Try to match a category in the user message
        matched_category = None
        for cat in categories:
            if cat in user_message:
                matched_category = cat
                break

        if matched_category:
            cat_products = sorted(set(p.name for p in products if p.category.lower() == matched_category))
            if cat_products:
                return jsonify({
                    "reply": f"Products in category '{matched_category.title()}': {', '.join(cat_products)}"
                })
            else:
                return jsonify({
                    "reply": f"No products found in category '{matched_category.title()}'."
                })

        # No specific category detected
        formatted_categories = ", ".join(cat.title() for cat in categories)
        return jsonify({
            "reply": f"I couldn't detect a specific category. Available categories: {formatted_categories}"
        })

    # Step 5: Quantity handling
    if session.get("pending_quantity_product"):
        quantity, _ = extract_quantity_and_packing(user_message)
        if quantity is None:
            return jsonify({"reply": "Please specify the quantity as a number, e.g. '2 units'."})

        product_name = session["pending_quantity_product"]
        packing = session["pending_quantity_packing"]
        matched_product = next(
            (p for p in Products.query.all() if p.name.lower() == product_name and p.availablePacking.lower() == packing),
            None
        )
        if not matched_product:
            return jsonify({"reply": "Sorry, that product is no longer available."})

        success, message = add_product_to_cart_by_id(matched_product.id, quantity)
        if success:
            session.pop("pending_quantity_product", None)
            session.pop("pending_quantity_packing", None)
            return jsonify({"reply": message})
        else:
            return jsonify({"reply": message})

    # Step 6: Product and packing detection
    products = Products.query.all()
    product_names = [p.name.lower() for p in products]
    categories = list(set(p.category.lower() for p in products))

    product_name = None
    packing_match = None
    for p in products:
        if f" {p.name.lower()} " in f" {user_message} ":
            product_name = p.name.lower()
        if p.availablePacking and p.availablePacking.lower() in user_message:
            packing_match = p.availablePacking.lower()

    quantity, detected_packing = extract_quantity_and_packing(user_message)
    if detected_packing and not packing_match:
        packing_match = detected_packing

    # Step 7: Both product and packing known
    if product_name and packing_match:
        matched_product = next(
            (p for p in products if p.name.lower() == product_name and p.availablePacking.lower() == packing_match),
            None
        )
        if matched_product:
            if quantity is None:
                session["pending_quantity_product"] = product_name
                session["pending_quantity_packing"] = packing_match
                return jsonify({"reply": f"{matched_product.name} ({matched_product.availablePacking}) is available. How many units would you like?"})
            else:
                success, message = add_product_to_cart_by_id(matched_product.id, quantity)
                return jsonify({"reply": message})
        else:
            return jsonify({"reply": f"Sorry, {product_name} with {packing_match} is not available."})

    # Step 8: Product known but packing not specified
    if product_name and not packing_match:
        matched_packings = [p for p in products if p.name.lower() == product_name]
        if not matched_packings:
            return jsonify({"reply": f"Sorry, '{product_name}' is not available."})
        session["pending_product"] = product_name
        session["pending_packings"] = list(set(p.availablePacking for p in matched_packings))
        packings_text = ", ".join(session["pending_packings"])
        return jsonify({"reply": f"Which packing would you like for {product_name}? Available: {packings_text}"})

    # Step 9: Packing selection pending
    if session.get("pending_product"):
        pending_product = session["pending_product"]
        available_packings = session.get("pending_packings", [])
        user_packing = next((p.lower() for p in available_packings if p.lower() in user_message), None)
        if user_packing:
            matched_product = next(
                (p for p in products if p.name.lower() == pending_product and p.availablePacking.lower() == user_packing),
                None
            )
            if matched_product:
                session["pending_quantity_product"] = pending_product
                session["pending_quantity_packing"] = user_packing
                session.pop("pending_product", None)
                session.pop("pending_packings", None)
                return jsonify({"reply": f"{matched_product.name} ({matched_product.availablePacking}) is available. How many units would you like?"})
            else:
                return jsonify({"reply": f"Sorry, {pending_product} with {user_packing} is not available."})

    # Final fallback
    return jsonify({"reply": "Sorry, I didn't understand that. Please try again or specify the product, packing, and quantity."})

#---chatbot functionality completed------
#----cart functionality-----
#-------cart function to store products from chatbot-----------
def add_product_to_cart_by_id(product_id, quantity):
    if "user" not in session:
        return False, "Please login first."

    product = Products.query.filter_by(id=product_id).first()
    if not product:
        return False, "Product not found."

    if not product.available:
        return False, f"'{product.name}' is not available."

    if product.quantity <= 0:
        return False, f"No stock available for '{product.name}'."

    final_qty = min(quantity, product.quantity)
    cart = session.get("cart", {})
    key = f"{product.name} ({product.availablePacking})"
    cart[key] = cart.get(key, 0) + final_qty
    session["cart"] = cart

    if quantity > product.quantity:
        return True, f"Only {product.quantity} units of '{product.name}' were available, so we added that."
    else:
        return True, f"Added {final_qty} units of '{product.name}' to your cart."
#-----cart function to store products from recommmendations and table row-----------
@app.route("/add_to_cart", methods=["POST"])
def add_to_cart():
    if "user" not in session:
        return jsonify({"status": "error", "message": "Please login first"}), 401

    data = request.get_json()
    product_id = data.get("productId")
    product_name = data.get("productName") or data.get("product")
    packing = data.get("packing")
    requested_qty = int(data.get("quantity", 1))

    # Find product
    product = None
    if product_id:
        product = Products.query.filter_by(id=product_id).first()
    elif product_name and packing:
        product = Products.query.filter_by(name=product_name, availablePacking=packing).first()
    elif product_name:
        product = Products.query.filter_by(name=product_name, available=True).first()

    if not product:
        return jsonify({"status": "error", "message": "Product not found"})

    # Add product to cart using helper
    success, message = add_product_to_cart_by_id(product.id, requested_qty)

    if success:
        return jsonify({
            "status": "success",
            "message": message,
            "cart": session.get("cart", {})
        })
    else:
        return jsonify({
            "status": "error",
            "message": message
        })
@app.route("/cart")
def cart():
    if "user" not in session:
        return redirect(url_for("login"))

    cart = session.get("cart", {})
    cart_items = []
    total_amount = 0

    for key, qty in cart.items():
        try:
            # key format: "Product Name (Packing)"
            name, packing = key.rsplit("(", 1)
            name = name.strip()
            packing = packing.strip(")")
        except ValueError:
            # Malformed key, skip
            continue

        product = Products.query.filter_by(name=name, availablePacking=packing).first()
        if product:
            subtotal = product.price * qty
            total_amount += subtotal
            cart_items.append({
                "name": product.name,
                "packing": product.availablePacking,
                "price": product.price,
                "quantity": qty,
                "subtotal": subtotal
            })
    
    return render_template("cart.html", cart_items=cart_items, total=total_amount)
#---cart functionality ended-----
#---Bill Generation-------
import qrcode
import base64
from io import BytesIO
@app.route("/bill")
def bill():
    order_id = session.get("last_order_id")
    order = Orders.query.get(order_id)

    if order:
        items = json.loads(order.items)

        upi_id = "9215667835@okbizaxis"
        amount = order.total
        upi_link = f"upi://pay?pa={upi_id}&pn=ShopiBot&am={amount}&cu=INR"

        qr = qrcode.make(upi_link)
        buf = BytesIO()
        qr.save(buf, format="PNG")
        qr_b64 = base64.b64encode(buf.getvalue()).decode("utf-8")

        return render_template("bill.html", order=order, items=items, qr_code=qr_b64)
    else:
        return "No order found"

#--------Bill functionality completed--------
#--------Download bill-------------------
from xhtml2pdf import pisa
import io
import json
@app.route("/download_bill")
def download_bill():
    order_id = session.get("last_order_id")
    if not order_id:
        return "No recent order to download"

    order = Orders.query.get(order_id)
    if not order:
        return "Order not found"

    try:
        items = json.loads(order.items)
    except:
        return "Invalid order data"

    
    upi_id = "9215667835@okbizaxis"
    amount = "{:.2f}".format(order.total)
    upi_link = f"upi://pay?pa={upi_id}&pn=ShopiBot&am={amount}&cu=INR"

    qr = qrcode.make(upi_link)
    buf = BytesIO()
    qr.save(buf, format="PNG")
    qr_b64 = base64.b64encode(buf.getvalue()).decode("utf-8")

    
    html = render_template("bill_pdf.html", order=order, items=items, qr_code=qr_b64)

    result = io.BytesIO()
    pdf = pisa.pisaDocument(io.StringIO(html), dest=result)

    if pdf.err:
        return "PDF generation failed"

    response = make_response(result.getvalue())
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = 'attachment; filename=ShopiBot_Bill.pdf'
    return response


#--------download bill functionality completed------
#---------Admin panel functionalities----------
#--------view users route---------
@app.route("/view-users")
def view_users():
    all_users = Users.query.all()

    # Collect currently logged-in users from the global dict
    current_users = []
    for u in logged_in_users.values():
        current_users.append({
            "username": u["username"],
            "email": u["email"]
        })

    return render_template("view_users.html", all_users=all_users, logged_in_users=current_users)

#-------view orders route---------------
@app.route("/view_orders")
def view_orders():
    if "role" not in session or session["role"] != "admin":
        flash("Access denied! Admins only.", "error")
        return redirect(url_for("login"))

    orders = Orders.query.all()
    order_data = []

    for order in orders:
        parsed_items = []
        if order.items:
            try:
                parsed_items = json.loads(order.items)
                if isinstance(parsed_items, str):
                    parsed_items = json.loads(parsed_items)

                if not isinstance(parsed_items, list):
                    parsed_items = []
            except Exception as e:
                print(f"Error parsing order {order.id}: {e}")
                parsed_items = []

        order_data.append({
            "id": order.id,
            "name": order.name,
            "items": parsed_items
        })

    return render_template("view_orders.html", orders=order_data)

#----------add products route---------------------
from sqlalchemy import func
@app.route("/addProducts", methods=["POST", "GET"])
def addProducts():
    if request.method == "POST":
        Entered_name = request.form["name"].strip()
        Entered_category = request.form["category"].strip()
        Entered_prices = request.form["price"].strip()
        Entered_quantity = request.form["quantity"].strip()
        Entered_availablePacking = request.form["availablePacking"].strip()
        Entered_unit = request.form["unit"].strip()
        Entered_description = request.form["description"].strip()

        # Split inputs into lists
        packings = [p.strip() for p in Entered_availablePacking.split(",") if p.strip()]
        prices = [p.strip() for p in Entered_prices.split(",") if p.strip()]

        # Check if packings and prices match
        if len(packings) != len(prices):
            return render_template(
                "add_products.html",
                error="Number of prices must match number of packings."
            )

        for packing, price in zip(packings, prices):
            # Check if product already exists (case-insensitive + ignore spaces in packing)
            existing_product = Products.query.filter(
                func.lower(Products.name) == Entered_name.lower(),
                func.replace(func.lower(Products.availablePacking), " ", "") ==
                packing.lower().replace(" ", "")
            ).first()

            if existing_product:
                # Increase quantity if already exists
                existing_product.quantity += int(Entered_quantity)
                existing_product.price = float(price) 
                existing_product.category = Entered_category
                existing_product.unit = Entered_unit
                existing_product.description = Entered_description
            else:
                # Add new product row
                new_product = Products(
                    name=Entered_name,
                    category=Entered_category,
                    price=float(price),
                    quantity=int(Entered_quantity),
                    availablePacking=packing,
                    unit=Entered_unit,
                    description=Entered_description
                )
                db.session.add(new_product)

        db.session.commit()
        return render_template("add_products.html", success=True)

    return render_template("add_products.html")

#-----------add products functionality completed-------------------------
#-------------Default values to products table-------------------------
items = [
    Products(name="Cheese", category="Dairy",availablePacking ="200 g",price=90, quantity=100, unit="g", description="Rich, creamy, and full of flavor — our fresh cheese is perfect for sandwiches, salads, or a quick snack."),
    Products(name="Desi Ghee", category="Dairy", availablePacking="1000 g",price=800, quantity=20, unit="g", description="Pure and aromatic, our desi ghee is made from the finest quality milk, adding rich flavor and wholesome goodness to every dish."),
    Products(name="Turmeric", category="Spices",availablePacking="500 g",price=80, quantity=100, unit="g", description="Bright and aromatic, our turmeric is packed with natural flavor and vibrant color, perfect for enhancing curries, teas, and everyday cooking."),
    Products(name="Turmeric", category="Spices",availablePacking="1000 g", price=150, quantity=50, unit="g", description="Bright and aromatic, our turmeric is packed with natural flavor and vibrant color, perfect for enhancing curries, teas, and everyday cooking."),
    Products(name="Coconut Biscuit", category="Snacks", availablePacking="100 g",price=10, quantity=100, unit="g", description="Crispy and sweet coconut-flavored biscuits for a delightful snack."),
    Products(name="Bakery Biscuit", category="Snacks",availablePacking="250 g", price=40, quantity=100, unit="g", description="Freshly baked biscuits with a rich buttery taste."),
    Products(name="Oreo Biscuit", category="Snacks", availablePacking="80 g",price=10, quantity=100, unit="g", description="Delicious chocolate biscuits with creamy filling."),
    Products(name="Haldiram Namkeen", category="Snacks",availablePacking="150 g", price=200, quantity=50, unit="g", description="Crispy and spicy Haldiram namkeen perfect for tea time."),
    Products(name="Bikanery Namkeen", category="Snacks",availablePacking="170 g", price=190, quantity=50, unit="g", description="Tasty and crunchy Bikaneri namkeen made with authentic spices."),
    Products(name="Rice", category="Grains",availablePacking="1000 g", price=90, quantity="100", unit="g", description="Premium quality rice for everyday cooking."),
    Products(name="Atta", category="Grains", availablePacking="5000 g",price=230, quantity=100, unit="g", description="Freshly milled wheat flour for soft rotis and parathas."),
    Products(name="Atta", category="Grains",availablePacking="10000 g", price=430, quantity=100, unit="g", description="Freshly milled wheat flour for soft rotis and parathas."),
    Products(name="Refined", category="Grocery", availablePacking="900 g",price=200, quantity=80, unit="g", description="Refined flour perfect for baking and cooking."),
    Products(name="Moong Dal", category="Pulses", availablePacking="500 g",price=60, quantity=80, unit="g", description="Fresh and clean moong dal rich in protein."),
    Products(name="Chana Dal", category="Pulses", availablePacking="500 g",price=70, quantity=80, unit="g", description="Nutritious chana dal ideal for dal fry and curries."),
    Products(name="Rajma", category="Pulses", availablePacking="500 g",price=90, quantity=70, unit="g", description="High-quality red kidney beans for flavorful dishes."),
    Products(name="Sugar", category="Grocery",availablePacking="500 g", price=25, quantity=50, unit="g", description="Pure refined sugar for everyday use."),
    Products(name="Tea", category="Beverages",availablePacking="500 g", price=270, quantity=40, unit="g", description="Premium tea leaves for a refreshing brew."),
    Products(name="Salt", category="Grocery",availablePacking="1000 g", price=20, quantity=100, unit="g", description="Pure and natural salt for cooking."),
    Products(name="Brown Bread", category="Bakery",availablePacking="400 g", price=40, quantity=30, unit="g", description="Healthy brown bread made from whole wheat."),
    Products(name="White Bread", category="Bakery",availablePacking="400 g", price=30, quantity=40, unit="g", description="Soft and fresh white bread for sandwiches."),
    Products(name="Chilli Powder", category="Spices",availablePacking="200 g", price=70, quantity=50, unit="g", description="Fiery red chilli powder for bold and spicy flavor."),
    Products(name="Cumin Seeds", category="Spices",availablePacking="100 g", price=140, quantity=50, unit="g", description="Aromatic cumin seeds to enhance flavor in your dishes.")
]

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        for item in items:
            exists = Products.query.filter_by(name=item.name , availablePacking = item.availablePacking).first()
            if not exists:
                db.session.add(item)
        db.session.commit()
    app.run(debug=True)


