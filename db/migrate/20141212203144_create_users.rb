class CreateUsers < ActiveRecord::Migration
  def change
      def change
    create_table :users do |t|
      t.string :name
      t.string :email
      t.string :password
      t.integer :group_id
    end
  end
end
