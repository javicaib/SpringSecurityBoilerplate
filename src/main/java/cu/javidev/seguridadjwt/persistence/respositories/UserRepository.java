package cu.javidev.seguridadjwt.persistence.respositories;

import cu.javidev.seguridadjwt.persistence.entities.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<UserEntity, Long> {
}