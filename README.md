We assessed commit `# 0da6c131ca38de43f3236b6da739912321074fd9`

# Findings

## Weak Password Policy

### Description

The application has a weak password policy allowing user's to have a 6 character password. This configuration seen on the following line of code <https://github.com/selinafeng/todo-app/blob/f6cc0df12a8617644b1c6b5781c6d33fd6ae5414/config/initializers/devise.rb#L162>

### Recommendation

We recommend changing the configuration to the following 

```ruby
...
config.password_length = 10..128
...
```

## Production Configuration Does Not Enforce TLS Encryption

### Description

The prod configuration file does not enforce encryption. This could be potentially dangerous as user's session tokens and credentials will be sent to the server in plaintext. The configuration which enforces this TLS was commented out on the following line of code <https://github.com/selinafeng/todo-app/blob/61d1f9d54a5fea80b604a7e037cca3cde77a67fa/config/environments/production.rb#L48>

### Recommendation

We recommend uncommenting the line of code which enforces TLS for production.

```ruby
...
config.force_ssl = true
...
```

## No Session Timeouts

### Description

The devise configuration does not include a session timeout, as a result, session are valid until the user logs themself out. This extends the window of oppertunity available for an attacker to compromise the session token. This issues is exacerbated by the fact the production does not enforce TLS. The session timeout configuration is commented out in the following line of code <https://github.com/selinafeng/todo-app/blob/f6cc0df12a8617644b1c6b5781c6d33fd6ae5414/config/initializers/devise.rb#L172>

### Recommendation

We recommend uncommenting the line of code as shown below:

```ruby
...
config.timeout_in = 30.minutes
...
```

## Controller Does Not Prevent Access From Anonymous Users

### Description

The controller does not prevent anonymous users from accessing the application. With this access anonymous users can create, read, update and delete TODOs belonging to any user. The affected code is in the following file: <https://github.com/selinafeng/todo-app/blob/61d1f9d54a5fea80b604a7e037cca3cde77a67fa/app/controllers/todos_controller.rb#L2>

### Recommendation

We recommend restricting access to TODO to authenticated users only by using a decorator similar to the following:

```ruby
before_action :authenticate_user!
```

## Component with known vulnerabilities

### Description

The application uses components with known vulnerabilities.

```text
Security Warnings
Confidence	Class	Method	Warning Type	Message
Medium 			Cross-Site Scripting 	loofah gem 2.1.1 is vulnerable (CVE-2018-8048). Upgrade to 2.2.1 near line 92

Medium 			Cross-Site Scripting 	
rails-html-sanitizer 1.0.3 is vulnerable (CVE-2018-3741). Upgrade to rails-html-sanitizer 1.0.4 near line 128
```

### Recommendation

We recommend updating all dependencies to the latest version by running the following command.

```bash
$ bundle update
```

---

# Notes for you/your team

## Behavior

* What does it do? (business purpose)
  * TODO List creation and management
  
* Who does it do this for? (internal / external customer base)
  * External any user can sign up 

* What kind of information will it hold?
  * Users TODO Information and notes associated with a TODO 

* What are the different types of roles?
  * Authenticated 
  * Anon

* What aspects concern your client/customer/staff the most?

## Tech Stack

* Framework & Language
  * Rails/Ruby
* 3rd party components, Examples:
  * gem 'rails', '~> 5.1.4'
  * gem 'sqlite3'
  * gem 'puma', '~> 3.7'
  * gem 'sass-rails', '~> 5.0'
  * gem 'uglifier', '>= 1.3.0'
  * gem 'coffee-rails', '~> 4.2'
  * gem 'turbolinks', '~> 5'
  * gem 'jbuilder', '~> 2.5'
  * gem 'bcrypt', '~> 3.1.7'
  * gem 'bootstrap-sass', '~> 3.2.0'
  * gem 'autoprefixer-rails'
  * gem 'jquery-rails'
  * gem 'devise'
  * gem 'tzinfo-data', platforms: [:mingw, :mswin, :x64_mingw, :jruby]
  * Bcrypt  
  * jquery rails
  * devise for authentication
* Datastore
  * SQLite

## Brainstorming / Risks

* Accessing other people's TODOs
* Injections, XSS
* CSRF
* User session handlling
* Handling credentials
* Access of TODOs by unauthenticated user's
* Password reset feature vulnerabilities
  * Brute forcible code
* authentication issues
* Use of many third party components
* Lack of auditing / logging
* Cookie signing with a static key
* Debug mode, verbose error messages
* CSP
* Production environment not configured to use TLS
* Cookies don't expire maybe
* Vulnerabilities in third party libraries

## Checklist of things to review based on Brainstorming and Tech Stack

- [ ] Check for user authentication mechanisms
- [ ] Check password policy
- [ ] Check session timout
- [ ] Check for SQL injection
- [ ] Check third party components for vulnerabilities
- [ ] Check for direct object reference issues / anonoymous access issues
- [ ] Check for CSRF protections

## Mapping / Routes
```text
                  Prefix Verb   URI Pattern                    Controller#Action
        new_user_session GET    /users/sign_in(.:format)       devise/sessions#new
            user_session POST   /users/sign_in(.:format)       devise/sessions#create
    destroy_user_session DELETE /users/sign_out(.:format)      devise/sessions#destroy
       new_user_password GET    /users/password/new(.:format)  devise/passwords#new
      edit_user_password GET    /users/password/edit(.:format) devise/passwords#edit
           user_password PATCH  /users/password(.:format)      devise/passwords#update
                         PUT    /users/password(.:format)      devise/passwords#update
                         POST   /users/password(.:format)      devise/passwords#create
cancel_user_registration GET    /users/cancel(.:format)        devise/registrations#cancel
   new_user_registration GET    /users/sign_up(.:format)       devise/registrations#new
  edit_user_registration GET    /users/edit(.:format)          devise/registrations#edit
       user_registration PATCH  /users(.:format)               devise/registrations#update
                         PUT    /users(.:format)               devise/registrations#update
                         DELETE /users(.:format)               devise/registrations#destroy
                         POST   /users(.:format)               devise/registrations#create
                   todos GET    /todos(.:format)               todos#index
                    - Lists all TODOs regardless of who they were created by
                    
                         POST   /todos(.:format)               todos#create
                    - Creates a new TODO and redirects to the TODO page.
                    
                new_todo GET    /todos/new(.:format)           todos#new
                    - Get request to load create todo form

               edit_todo GET    /todos/:id/edit(.:format)      todos#edit
                    - GET request to load edit form

                    todo GET    /todos/:id(.:format)           todos#show
                    - Show details of a particular todo

                         PATCH  /todos/:id(.:format)           todos#update
                              - Update a particulat todo
                         PUT    /todos/:id(.:format)           todos#update
                              - Update a particulat todo
                         DELETE /todos/:id(.:format)           todos#destroy
                              - Delete a particulat TODO
                    root GET    /                              todos#index
```
## Mapping / Authorization Decorators

- [ ] none

## Mapping / Files

- [ ] /path/to/some/important/file.sh

