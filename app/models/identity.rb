class Identity < OmniAuth::Identity::Models::ActiveRecord

  belongs_to :user
  auth_key :uid

  # Uid attribute needs to be redefined to returned our stored value because class 
  # OmniAuth::Identity::Models::ActiveRecord defines an uid attribute that returns the id value as a string.
  def uid
    self[:uid]
  end

  def uid=(value)
    self[:uid] = value
  end

  # Clear previous set validators because the parent class OmniAuth::Identity::Models::ActiveRecord includes
  # has_secure_password and adds validators for password values being present. As we have other login strategies we only
  # need password being present for the 'identity' provider which represent system accounts.
  clear_validators!
  validates :provider, presence: true
  validates :uid, presence: true, uniqueness: { scope: :provider }
  validates :user_id, uniqueness: { scope: :provider }

  # Check if the password is present only when working with system accounts
  validates :password, presence: true, if: lambda { |identity|
    identity.provider == 'identity'
  }

end
