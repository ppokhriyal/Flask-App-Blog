import os
import markdown
import secrets
import bleach
from bleach.sanitizer import Cleaner
from PIL import Image
from flask import render_template, url_for, flash, redirect, request, abort, session
from vxlkblog import app, db, bcrypt, mail, login_manager, mde
from vxlkblog.forms import RegistrationForm, LoginForm, UpdateAccountForm, PostForm, RequestRestForm, ResetPasswordForm
from vxlkblog.models import User, Post
from flask_login import login_user, current_user, logout_user, login_required
from flask_mail import Message


#Index Page
@app.route('/')
@app.route('/index')
def index():
	page = request.args.get('page',1,type=int)
	posts = Post.query.order_by(Post.date_posted.desc()).paginate(page=page,per_page=4)
	len_post = len(Post.query.all())
	return render_template('index.html',posts=posts,len_post=len_post,title='Index')


#Register Page
@app.route('/register',methods=['GET','POST'])
def register():
	if current_user.is_authenticated:
		return redirect(url_for('index'))
	form = RegistrationForm()
	if form.validate_on_submit():
		hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
		user = User(username=form.username.data, email=form.email.data, password=hashed_password)
		db.session.add(user)
		db.session.commit()
		flash(f'Your Account has been created! You are now able to login','success')
		return redirect(url_for('login'))

	return render_template('register.html',form=form,title='Register')

#Admin Home Page
@app.route('/admin_home')
@login_required
def admin_home():
	users_count = db.session.query(User).count() - 1
	users_emails_list = [x[0] for x in db.session.query(User.email).filter(User.email != 'admin@vxlsoftware.com').all()]
	user_dict = {}
	for i in users_emails_list:
		user_dict[i] = db.session.query(User.email).filter(User.email == i ).join(Post).count()

	return render_template('admin_home.html',title='Administrator',users_count=users_count,user_dict = user_dict)

#Login Page
@app.route('/login',methods=['GET','POST'])
def login():
	form = LoginForm()
	if form.validate_on_submit():
		user = User.query.filter_by(email=form.email.data).first()
		if user and bcrypt.check_password_hash(user.password,form.password.data):
			login_user(user,remember=form.remember.data)
			next_page = request.args.get('next')
			if form.email.data == 'admin@vxlsoftware.com':
				return redirect(next_page) if next_page else redirect(url_for('admin_home'))
			else:
				return redirect(next_page) if next_page else redirect(url_for('index'))
		else:
			flash('Login Unsuccessful. Please check email and password','danger')

	return render_template('login.html',form=form,title='Login')

#Logout
@app.route('/logout')
def logout():
	logout_user()
	return redirect(url_for('index'))


#Function for Saving Profile Picture
def save_pictute(form_picture):
	renadom_hex = secrets.token_hex(8)
	_, f_ext = os.path.splitext(form_picture.filename)
	picture_fn = renadom_hex + f_ext
	picture_path = os.path.join(app.root_path,'static/profile_pics',picture_fn)
	output_size = (125,125)
	i = Image.open(form_picture)
	i.thumbnail(output_size)
	i.save(picture_path)
	return picture_fn


#Account next_page
@app.route('/account',methods=['GET','POST'])
@login_required	
def account():
	form = UpdateAccountForm()
	if form.validate_on_submit():
		if form.picture.data:
			picture_file = save_pictute(form.picture.data)
			current_user.image_file = picture_file

		current_user.username = form.username.data
		current_user.email = form.email.data
		db.session.commit()
		flash('Your account has been updated!','success')
		return redirect(url_for('account'))
	elif request.method == 'GET':
		form.username.data = current_user.username
		form.email.data = current_user.email	
	image_file = url_for('static',filename='profile_pics/' + current_user.image_file)
	return render_template('account.html',title='Account',image_file=image_file,form=form)	

#Posts Page
@app.route('/post/new',methods=['GET','POST'])
@login_required
def new_post():
	form = PostForm()
	if form.validate_on_submit():
		session['content'] = request.form['content']
		html = markdown.markdown(request.form['content'])
		# Tags deemed safe
		allowed_tags = [
		'a','abbr','acronym','b','blockquote','code',
		'em','i','li','ol','pre','strong','ul','img',
		'h1','h2','h3','p','br'
		]
		# Attributes deemed safe
		allowed_attrs = {
		'*':['class'],
		'a':['href','rel'],
		'img':['src','alt']
		}
		# Sanitize HTML
		html_sanitized = bleach.clean(
			bleach.linkify(html),
			tags=allowed_tags,
			attributes=allowed_attrs
			)
		post = Post(title=form.title.data,content=html_sanitized,author=current_user,category=form.category_name.data)
		db.session.add(post)
		db.session.commit()
		flash('Your post has been created!','success')
		return redirect(url_for('index'))
	return render_template('create_post.html',title='New Post',form=form,legend='New Post')

#Edit Post
@app.route('/post/<int:post_id>')
def post(post_id):
	post = Post.query.get_or_404(post_id)
	return render_template('post.html',title=post.title,post=post)

#Update Post
@app.route('/post/<int:post_id>/update',methods=['GET','POST'])
@login_required
def update_post(post_id):
	post = Post.query.get_or_404(post_id)
	if post.author != current_user:
		abort(403)
	form = PostForm()
	if form.validate_on_submit():
		post.title = form.title.data
		post.content = form.content.data
		db.session.commit()
		flash('Your post has been updated!','success')
		return redirect(url_for('post',post_id=post_id))
	elif request.method == 'GET':
		form.title.data = post.title
		form.content.data = post.content
	return render_template('create_post.html',title='Update Post',form=form,legend='Update Post')	

#Delete Post
@app.route('/post/<int:post_id>/delete',methods=['POST'])
@login_required
def delete_post(post_id):
	post = Post.query.get_or_404(post_id)
	if post.author != current_user	:
		abort(403)
	db.session.delete(post)
	db.session.commit()
	flash('Your post has been deleted!','success')
	return redirect(url_for('index'))

#Delete Users
@app.route('/delete_user/<string:user_del_email>',methods=['POST'])
@login_required
def delete_user(user_del_email):
	user_id = db.session.query(User.id).filter(User.email == user_del_email).all()
	user_remove = db.session.query(User).get_or_404(user_id[0])
	db.session.delete(user_remove)
	db.session.commit()
	flash('User has been deleted!','success')
	return redirect(url_for('admin_home'))

#Update User Information
@app.route('/admin_home/user_info_update/<string:user_info_email>',methods=['GET','POST'])
@login_required
def user_info_update(user_info_email):
	form = ResetPasswordForm()
	user_name = [x[0] for x in db.session.query(User.username).filter(User.email == user_info_email).all()]
	user_info_dict = {"username": user_name[0],"useremail": user_info_email}

	if form.validate_on_submit():
		hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
		user_obj = User.query.filter_by(email=user_info_email).first()
		user_obj.password = hashed_password
		db.session.commit()
		flash('Password resetting done successfully','success')
		return redirect(url_for('admin_home'))
	return render_template('update_user_info.html',title='Update User Information',user_info_dict=user_info_dict,form=form)

#Categories List
@app.route("/index/categories/<string:catgname>")
def category(catgname):
	total_catg_post = db.session.query(Post).filter(Post.category == catgname).count()
	page = request.args.get('page',1,type=int)
	posts = Post.query.filter_by(category=catgname).order_by(Post.date_posted.desc()).paginate(page=page,per_page=4)
	

	return render_template('category_list.html',title='Categories',catgname=catgname,total_catg_post=total_catg_post,posts=posts)

#User Posts Order
@app.route("/user/<string:username>")
def user_posts(username):
	page = request.args.get('page',1,type=int)
	user = User.query.filter_by(username=username).first_or_404()
	posts = Post.query.filter_by(author=user)\
		.order_by(Post.date_posted.desc())\
		.paginate(page=page,per_page=4)
	return render_template('user_posts.html',posts=posts,user=user)


def send_reset_email(user):
	token = user.get_reset_token()
	msg = Message('Password Reset Request',sender=[user.email],recipients=[user.email])
	msg.body = f''' To reset your password, visit the following link :
{url_for('reset_token',token=token,_external=True)}

If you did not make this request then simply ignore this email.
'''
	mail.send(msg)

#Request Reset Form
@app.route('/reset_password',methods=['GET','POST'])
def reset_request():
	if current_user.is_authenticated:
		return redirect(url_for('index'))
	form = RequestRestForm()
	if form.validate_on_submit():
		user = User.query.filter_by(email=form.email.data).first()
		send_reset_email(user)
		flash('An email has been sent with instruction to reset your password.','info')
		return redirect(url_for('login'))
	return render_template('reset_request.html',title='Reset Password',form=form)

#Reset Password
@app.route('/reset_password/<token>',methods=['GET','POST'])
def reset_token(token):
	if current_user.is_authenticated:
		return redirect(url_for('index'))
	user = User.verify_reset_token(token)
	if user is None:
		flash('That is an invalid or expired token','warning')
		return redirect(url_for('reset_request'))
	form = ResetPasswordForm()
	if form.validate_on_submit():
		hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
		user.password = hashed_password
		db.session.commit()
		flash(f'Your Password has been updated! You are now able to login','success')
		return redirect(url_for('login'))
	return render_template('reset_token.html',title='Reset Password',form=form)		

