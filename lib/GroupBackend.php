<?php
/**
 * @copyright Copyright (c) 2018 Richard Lowe <richard.lowe@arkivum.com>
 *
 * @license GNU AGPL version 3 or any later version
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

namespace OCA\User_SAML;

use OCP\DB\QueryBuilder\IQueryBuilder;
use OCP\IDBConnection;
use OCP\GroupInterface;
use OCP\IConfig;
use OCP\IGroupManager;
use OCP\ISession;

/**
 * Class for group management using SAML attributes. Based on OC\Group\Database
 * implementation.
 */
class GroupBackend implements GroupInterface {
	/** @var IConfig */
	private $config;
	/** @var ISession */
	private $session;
	/** @var IDBConnection */
	private $db;
	/** @var IGroupManager */
	private $groupManager;
	/** @var \OCP\GroupInterface[] */
	private static $backends = [];
	/** @var string[] */
	private $groupCache = [];

	/**
	 * @param IConfig $config
	 * @param ISession $session
	 * @param IDBConnection $db
	 * @param IGroupManager $groupManager
	 */
	public function __construct(IConfig $config,
								ISession $session,
								IDBConnection $db,
								IGroupManager $groupManager) {
		$this->config = $config;
		$this->session = $session;
		$this->db = $db;
		$this->groupManager = $groupManager;
	}
	

	/**
	 * Whether autoprovisioning is enabled or not
	 *
	 * @return bool
	 */
	public function autoprovisionAllowed() {
		return $this->config->getAppValue('user_saml', 'general-require_provisioned_account', '0') === '0';
	}
	
	/**
	 * Add a user to a group
	 * @param string $uid Name of the user to add to group
	 * @param string $gid Name of the group in which add the user
	 * @return bool
	 *
	 * Adds a user to a group.
	 */
	public function addToGroup( $uid, $gid ) {
		// No duplicate entries!
		if( !$this->inGroup( $uid, $gid )) {
			$qb = $this->db->getQueryBuilder();
			$qb->insert('user_saml_group_user')
				->setValue('uid', $qb->createNamedParameter($uid))
				->setValue('gid', $qb->createNamedParameter($gid))
				->execute();
			return true;
		}else{
			return false;
		}
	}
	
	/**
	 * get the number of all users matching the search string in a group
	 * @param string $gid
	 * @param string $search
	 * @return int|false
	 * @throws \OC\DatabaseException
	 */
	public function countUsersInGroup($gid, $search = '') {
		$parameters = [$gid];
		$searchLike = '';
		if ($search !== '') {
			$parameters[] = '%' . $this->dbConn->escapeLikeParameter($search) . '%';
			$searchLike = ' AND `uid` LIKE ?';
		}

		$stmt = \OC_DB::prepare('SELECT COUNT(`uid`) AS `count` FROM `*PREFIX*user_saml_group_user` WHERE `gid` = ?' . $searchLike);
		$result = $stmt->execute($parameters);
		$count = $result->fetchOne();
		if($count !== false) {
			$count = (int)$count;
		}
		return $count;
	}
	
	/**
	 * Try to create a new group
	 * @param string $gid The name of the group to create
	 * @return bool
	 *
	 * Tries to create a new group. If the group name already exists, false will
	 * be returned.
	 */
	public function createGroup( $gid ) {
		// Add group
		$result = $this->db->insertIfNotExist('*PREFIX*user_saml_groups', [
			'gid' => $gid,
		]);
		// Add to cache
		$this->groupCache[$gid] = $gid;
		return $result === 1;
	}
	
	/**
	 * delete a group
	 * @param string $gid The name of the group to delete
	 * @return bool
	 */
	public function deleteGroup($gid) {
		if($this->groupExistsInDatabase($gid)) {
			// Delete the group
			$qb = $this->db->getQueryBuilder();
			$qb->delete('user_saml_groups')
				->where($qb->expr()->eq('gid', $qb->createNamedParameter($gid)))
				->execute();
	
			// Delete the group-user relation
			$qb = $this->db->getQueryBuilder();
			$qb->delete('user_saml_group_user')
				->where($qb->expr()->eq('gid', $qb->createNamedParameter($gid)))
				->execute();
	
			// Delete from cache
			unset($this->groupCache[$gid]);

			return true;
		}
		return false;
	}
	
	/**
	 * Gets the actual group backend of the group
	 *
	 * @param string $uid
	 * @return null|UserInterface
	 */
	public function getActualGroupBackend($gid) {
		foreach(self::$backends as $backend) {
			if($backend->groupExists($gid)) {
				return $backend;
			}
		}

		return null;
	}
	 
	/**
	 * get a list of all groups
	 * @param string $search
	 * @param int $limit
	 * @param int $offset
	 * @return array an array of group names
	 *
	 * Returns a list with all groups
	 */
	public function getGroups($search = '', $limit = null, $offset = null) {
		$parameters = [];
		$searchLike = '';
		if ($search !== '') {
			$parameters[] = '%' . $search . '%';
			$searchLike = ' WHERE LOWER(`gid`) LIKE LOWER(?)';
		}

		$stmt = \OC_DB::prepare('SELECT `gid` FROM `*PREFIX*user_saml_groups`' . $searchLike . ' ORDER BY `gid` ASC', $limit, $offset);
		$result = $stmt->execute($parameters);
		$groups = array();
		while ($row = $result->fetchRow()) {
			$groups[] = $row['gid'];
		}
		return $groups;
	}
	
	/**
	 * Get all groups a user belongs to
	 * @param string $uid Name of the user
	 * @return array an array of group names
	 *
	 * This function fetches all groups a user belongs to. It does not check
	 * if the user exists at all.
	 */
	public function getUserGroups( $uid ) {
		//guests has empty or null $uid
		if ($uid === null || $uid === '') {
			return [];
		}

		// No magic!
		$qb = $this->db->getQueryBuilder();
		$cursor = $qb->select('gid')
			->from('user_saml_group_user')
			->where($qb->expr()->eq('uid', $qb->createNamedParameter($uid)))
			->execute();

		$groups = [];
		while( $row = $cursor->fetch()) {
			$groups[] = $row["gid"];
			$this->groupCache[$row['gid']] = $row['gid'];
		}
		$cursor->closeCursor();

		return $groups;
	}
	
	/**
	 * check if a group exists
	 * @param string $gid
	 * @return bool
	 */
	public function groupExists($gid) {
		if($backend = $this->getActualGroupBackend($gid)) {
			return $backend->groupExists($gid);
		}
		return $this->groupExistsInDatabase($gid);
	}
	
	/**
	 * Check if backend implements actions
	 * @param int $actions bitwise-or'ed actions
	 * @return boolean
	 * @since 4.5.0
	 *
	 * Returns the supported actions as int to be
	 * compared with \OC_Group_Backend::CREATE_GROUP etc.
	 */
	public function implementsActions($actions) {
		$availableActions = \OC\Group\Backend::COUNT_USERS;
		$availableActions |= \OC\Group\Backend::ADD_TO_GROUP;
		$availableActions |= \OC\Group\Backend::CREATE_GROUP;
		$availableActions |= \OC\Group\Backend::DELETE_GROUP;
		$availableActions |= \OC\Group\Backend::REMOVE_FROM_GROUP;
		return (bool)($availableActions & $actions);
	}
	
	/**
	 * is user in group?
	 * @param string $uid uid of the user
	 * @param string $gid gid of the group
	 * @return bool
	 *
	 * Checks whether the user is member of a group or not.
	 */
	public function inGroup( $uid, $gid ) {
		// check
		$qb = $this->db->getQueryBuilder();
		$cursor = $qb->select('uid')
			->from('user_saml_group_user')
			->where($qb->expr()->eq('gid', $qb->createNamedParameter($gid)))
			->andWhere($qb->expr()->eq('uid', $qb->createNamedParameter($uid)))
			->execute();

		$result = $cursor->fetch();
		$cursor->closeCursor();

		return $result ? true : false;
	}
	
	/**
	 * Registers the used backends, used later to get the actual group backend
	 * of the group.
	 *
	 * @param \OCP\GroupInterface[] $backends
	 */
	public function registerBackends(array $backends) {
		self::$backends = $backends;
	}
	
	/**
	 * Removes a user from a group
	 * @param string $uid Name of the user to remove from group
	 * @param string $gid Name of the group from which remove the user
	 * @return bool
	 *
	 * removes the user from a group.
	 */
	public function removeFromGroup( $uid, $gid ) {
		$qb = $this->db->getQueryBuilder();
		$qb->delete('user_saml_group_user')
			->where($qb->expr()->eq('uid', $qb->createNamedParameter($uid)))
			->andWhere($qb->expr()->eq('gid', $qb->createNamedParameter($gid)))
			->execute();

		return true;
	}
	
	public function setAdmin($userObject, $admin = false) {
		$adminGroup = $this->groupManager->get('admin');
		if($admin) {
			$adminGroup->addUser($userObject);
		} else {
			$adminGroup->removeUser($userObject);
		}
	}
	
	public function setGroupMembership($uid, array $newGroups, $asSubAdmin = false) {
		// Get the subadmin manager
		$subAdminManager = $this->groupManager->getSubAdmin();
		// Get existing groups for user
		$existingGroups = $this->getUserGroups($uid);
		// Add the user to any new groups, creating the groups if necessary
		$addToGroups = array_diff($newGroups, $existingGroups);
		foreach ($addToGroups as $group) {
			$this->createGroup($group);
			$this->addToGroup($uid, $group);
			if ($asSubAdmin) {
				$subAdminManager->addSubAdmin($uid, $group);
			}
		}
		// Remove the user from any old groups, deleting the groups if empty
		$removeFromGroups = array_diff($existingGroups, $newGroups);
		foreach ($removeFromGroups as $group) {
			if($subAdminManager->isSubAdmin($uid, $group)) {
				$subAdminManager->removeSubAdmin($uid, $group);
			}
			$this->removeFromGroup($uid, $group);
			if($this->countUsersInGroup($group) == 0) {
				// Group no longer in use
				$this->deleteGroup($group);
			}
		}
	}
	
	/**
	 * get a list of all users in a group
	 * @param string $gid
	 * @param string $search
	 * @param int $limit
	 * @param int $offset
	 * @return array an array of user ids
	 */
	public function usersInGroup($gid, $search = '', $limit = null, $offset = null) {
		$parameters = [$gid];
		$searchLike = '';
		if ($search !== '') {
			$parameters[] = '%' . $this->db->escapeLikeParameter($search) . '%';
			$searchLike = ' AND `uid` LIKE ?';
		}

		$stmt = \OC_DB::prepare('SELECT `uid` FROM `*PREFIX*user_saml_group_user` WHERE `gid` = ?' . $searchLike . ' ORDER BY `uid` ASC',
			$limit,
			$offset);
		$result = $stmt->execute($parameters);
		$users = array();
		while ($row = $result->fetchRow()) {
			$users[] = $row['uid'];
		}
		return $users;
	}
	
	protected function groupExistsInDatabase($gid) {
		// Check cache first
		if (isset($this->groupCache[$gid])) {
			return true;
		}

		$qb = $this->db->getQueryBuilder();
		$cursor = $qb->select('gid')
			->from('groups')
			->where($qb->expr()->eq('gid', $qb->createNamedParameter($gid)))
			->execute();
		$result = $cursor->fetch();
		$cursor->closeCursor();

		if ($result !== false) {
			$this->groupCache[$gid] = $gid;
			return true;
		}
		return false;
	}

}
