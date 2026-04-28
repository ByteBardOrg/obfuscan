class User < ApplicationRecord
  has_many :posts, dependent: :destroy
  validates :email, presence: true, uniqueness: true

  scope :active, -> { where(active: true) }

  def display_name
    name.presence || email.split("@").first
  end
end
